import logging
import os
import streamlit as st
from configparser import ConfigParser
# https://python.langchain.com/api_reference/langchain/chains/langchain.chains.conversational_retrieval.base.ConversationalRetrievalChain.html
from langchain.chains import (
    create_history_aware_retriever,
    create_retrieval_chain,
)
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain_chroma import Chroma
from langchain_community.document_loaders import DirectoryLoader, JSONLoader, TextLoader, UnstructuredMarkdownLoader
from langchain_core.messages import HumanMessage, AIMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_ollama import OllamaLLM, OllamaEmbeddings

from data_processing import (
    pcap_to_json,
    split_by_packet,
    split_by_stream
)

logging.basicConfig(filename='packet_buddy.log', encoding='utf-8',
                    format='[%(asctime)s][%(levelname)s] %(message)s', level=logging.DEBUG)

logger = logging.getLogger("packet_buddy")
logger.setLevel(logging.DEBUG)

config = ConfigParser()
config.read('config.ini')

OLLAMA_BASE_URL = config['ollama']['BASE_URL']
EMBEDDING_DEVICE = config['packet_buddy']['device']
EMBEDDING_MODEL = config['packet_buddy']['embedding_model']
LLM_MODEL = config['packet_buddy']['llm_model']
os.environ['OLLAMA_HOST'] = OLLAMA_BASE_URL

# Prompts
contextualize_q_system_prompt = (
    "Given a chat history and the latest user question "
    "which might reference context in the chat history, "
    "formulate a standalone question which can be understood "
    "without the chat history. Do NOT answer the question, just "
    "reformulate it if needed and otherwise return it as is."
)

system_prompt = """
    You are specialized in analyzing packets related data.
    Use the following information to answer user's question:

    {context}

    The following info are available the context contains information about network packets of a stream:
    - stream_number: the number of the TCP stream
    - frames: a list of frames in the stream, each containing:
        - frame.number: the number of the frame
        - frame.time_utc: the timestamp when the frame was captured
        - ip.version: the IP version used in the packet
        - ip.src: source IP address
        - ip.dst: destination IP address
        - tcp.srcport: source port number
        - tcp.dstport: destination port number
        - tcp.payload: TCP payload data if available
        - tcp.segment_data: TCP segment data if available
        - tcp_analysis_flags: any TCP analysis flags present

    Search within the context to provide the answer.
    If the anser cannot obtained from the context, respond with "I cannot answer that based on the packet data."
    Always provide the reasoning behind your answer, no matter you're able to answer the question or not.
    And briefly describe what you can find in the context.

    Format your response in markdown with line breaks.
"""


# Define a class for chatting with pcap data
class ChatWithPCAP:
    def __init__(self, pcap_path):
        self.embedding_model = OllamaEmbeddings(model=EMBEDDING_MODEL)
        # data location
        self.pcap_name = os.path.basename(pcap_path)
        self.data_location = os.path.dirname(pcap_path)
        self.load_data()
        self.vectordb = None
        self.llm = None
        self.rag_chain = None
        self.chat_history = []
        self.store_in_chroma()
        self.setup_conversation_retrieval_chain()

    def load_data(self):
        split_by_packet(f"{self.data_location}/{self.pcap_name}.json", "json")
        split_by_stream(f"{self.data_location}/{self.pcap_name}.json", "json")
        self.loader = DirectoryLoader(
            path=f"{self.data_location}/json",
            glob="*.json",
            loader_cls=lambda file_path: JSONLoader(
                file_path=file_path,
                jq_schema='.',
                text_content=False
            )
        )
        # self.loader = DirectoryLoader(
        #     path=f"{self.data_location}/markdown",
        #     glob="*.md",
        #     loader_cls=UnstructuredMarkdownLoader
        # )
        # self.loader = DirectoryLoader(
        #     path=f"{self.data_location}/txt",
        #     glob="*.txt",
        #     loader_cls=lambda file_path: TextLoader(
        #         file_path=file_path,
        #         autodetect_encoding=True
        #     )
        # )
        self.documents = self.loader.load()

    def store_in_chroma(self):
        persist_directory = "./chroma"
        # with st.spinner("Loading existing Chroma database..."):
        #     self.vectordb = Chroma(persist_directory=persist_directory, embedding_function=self.embedding_model)
        # # Check if database is empty or needs to be recreated
        # if self.vectordb._collection.count() == 0:
        #     with st.spinner("Database empty, storing documents in Chroma..."):
        #         self.vectordb.add_documents(self.documents)
        with st.spinner("Storing in Chroma..."):
            self.vectordb = Chroma.from_documents(
                documents=self.documents,
                embedding=self.embedding_model,
                persist_directory=persist_directory
            )

    def setup_conversation_retrieval_chain(self):
        self.llm = OllamaLLM(model=LLM_MODEL, base_url=OLLAMA_BASE_URL)
        # Ensure the vector database is used as a retriever
        retriever = self.vectordb.as_retriever(
            # Retrieve top k relevant documents, larger k may lead to better context but slower response
            search_kwargs={"k": 15}
        )
        contextualize_q_prompt = ChatPromptTemplate.from_messages([
            ("system", contextualize_q_system_prompt),
            MessagesPlaceholder("chat_history"),
            ("human", "{input}"),
        ])
        history_aware_retriever = create_history_aware_retriever(
            self.llm, retriever, contextualize_q_prompt
        )
        qa_prompt = ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            MessagesPlaceholder("chat_history"),
            ("human", "{input}"),
        ])
        question_answer_chain = create_stuff_documents_chain(
            self.llm, qa_prompt)
        self.rag_chain = create_retrieval_chain(
            history_aware_retriever, question_answer_chain)

    def chat(self, question):
        try:
            response = self.rag_chain.invoke({
                "input": question,
                # Keep last 5 exchanges (10 messages)
                "chat_history": self.chat_history[-10:]
            })
            logger.debug(response)

            if response and "answer" in response:
                # Update chat history
                self.chat_history.extend([
                    HumanMessage(content=question),
                    AIMessage(content=response["answer"])])
                return {'answer': response['answer']}
            else:
                return {'answer': "I couldn't generate a response based on the packet data. Please try rephrasing your question."}

        except Exception as e:
            st.error(f"Error during chat: {str(e)}")
            return {'answer': "An error occurred while processing your question."}


# Streamlit UI for uploading and converting pcap file
def upload_and_convert_pcap():
    st.title('Packet Buddy - Chat with pcap')
    uploaded_file = st.file_uploader("Choose a PCAP file", type="pcap")

    if uploaded_file:
        if not os.path.exists('packet_data'):
            os.makedirs('packet_data')
        pcap_path = os.path.join("packet_data", uploaded_file.name)

        with open(pcap_path, "wb") as f:
            f.write(uploaded_file.getvalue())

        pcap_to_json(pcap_path, f"{pcap_path}.json")
        st.session_state['pcap_path'] = pcap_path
        st.success("PCAP file uploaded and converted to JSON.")
        if st.button("Proceed to Chat"):
            st.session_state['page'] = 2
            st.rerun()


# Streamlit UI for chat interface
def chat_interface():
    st.title('Packet Buddy - Chat with pcap')

    pcap_path = st.session_state.get('pcap_path')
    if not pcap_path or not os.path.exists(f"{pcap_path}.json"):
        st.error(
            "PCAP file missing or not converted. Please go back and upload a PCAP file.")
        return

    with st.sidebar:
        if st.button("Clear Chat History"):
            st.session_state['chat_instance'].chat_history = []
            st.rerun()
        st.button("Upload New PCAP", on_click=lambda: setattr(
            st.session_state, 'page', 1))

    if 'chat_instance' not in st.session_state:
        st.session_state['chat_instance'] = ChatWithPCAP(pcap_path=pcap_path)

    for message in st.session_state['chat_instance'].chat_history:
        if isinstance(message, HumanMessage):
            with st.chat_message("user"):
                st.markdown(f"{message.content}")
        elif isinstance(message, AIMessage):
            with st.chat_message("assistant"):
                st.markdown(f"{message.content}")

    if user_input := st.chat_input("Ask a question about the PCAP data"):
        with st.chat_message("user"):
            st.markdown(f"{user_input}")

        with st.chat_message("assistant"):
            message_placeholder = st.empty()
            with st.spinner('Thinking...'):
                response = st.session_state['chat_instance'].chat(user_input)
                if isinstance(response, dict) and 'answer' in response:
                    full_response = response['answer']
                else:
                    full_response = "I couldn't analyze the packet data properly. Please try again."
            message_placeholder.markdown(full_response)


if __name__ == "__main__":
    if 'page' not in st.session_state:
        st.session_state['page'] = 1
    if st.session_state['page'] == 1:
        upload_and_convert_pcap()
    elif st.session_state['page'] == 2:
        chat_interface()
