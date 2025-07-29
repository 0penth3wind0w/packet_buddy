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

    The following info are available the context contains information about network packets:
    - tcp.stream: the ID number of the TCP stream
    - frames: a list of frames in the stream, each containing:
        - frame.number: the number of the frame
        - frame.len: the length of the frame
        - tcp.stream.pnum: the packet number in the TCP stream
        - frame.time_utc: the timestamp when the frame was captured
        - ip.src: source IP address
        - ip.dst: destination IP address
        - tcp.srcport: source port number
        - tcp.dstport: destination port number
        - tcp.payload: TCP payload data if available
        - tcp.segment_data: TCP segment data if available

    Provide the answer base on the context.
    If the answer cannot infer from the context, respond with "I cannot answer that based on the data."
    Always provide the reasoning behind your answer, no matter you're able to answer the question or not.
    And briefly describe what you can provide with the context.

    Format your response in markdown with the following format, add line breaks between sections:
    **Answer:**
    - Provide the answer to the question.
    **Reasoning:**
    - Explain how you arrived at the answer or why you cannot answer it.
    **What I can provide:**
    - Briefly describe what information you can provide based on the packet data.

"""


# Define a class for chatting with pcap data
class ChatWithPCAP:
    def __init__(self, pcap_path):
        self.embedding_model = OllamaEmbeddings(model=EMBEDDING_MODEL)
        self.llm_model = OllamaLLM(model=LLM_MODEL, base_url=OLLAMA_BASE_URL)
        # data location
        self.pcap_name = os.path.basename(pcap_path)
        self.data_location = os.path.dirname(pcap_path)
        self.load_data()
        # self.vectordb = None
        # self.rag_chain = None
        self.chat_history = []
        self.store_in_chroma()

    def load_data(self):
        def metadata_func(record: dict, metadata: dict) -> dict:
            metadata["tcp.stream"] = record.get("tcp.stream")
            return metadata
        # split_by_packet(f"{self.data_location}/{self.pcap_name}.json", "json")
        split_by_stream(f"{self.data_location}/{self.pcap_name}.json", "json")
        self.loader = DirectoryLoader(
            path=f"{self.data_location}/json",
            glob="*.json",
            loader_cls=lambda file_path: JSONLoader(
                file_path=file_path,
                jq_schema='.',
                text_content=False,
                metadata_func=metadata_func
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
        #     self.vectordb = Chroma(
        #         persist_directory=persist_directory, embedding_function=self.embedding_model)
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

    def document_filter_agent(self, question, chat_history):
        agent_system_prompt = (
            "You are an agent that filters documents based on the user's question."
            "Based on the question, determine if it is relevant to a specific packet stream."
            "If the question is relevant to a specific packet stream, return the stream number."
            "If the question is not relevant to any packet stream, return empty string."
            "No need to answer the question, just return the stream number or empty string"
        )
        agent_prompt = ChatPromptTemplate.from_messages([
            ("system", agent_system_prompt),
            MessagesPlaceholder("chat_history"),
            ("human", "{question}"),
        ])
        agent_chain = agent_prompt | self.llm_model
        response = agent_chain.invoke({"question": question, "chat_history": chat_history})
        logger.debug(f"Agent response: {response}")
        if response and isinstance(response, str):
            response = response.strip()
            if response.isdigit():
                return int(response)
            elif response == "":
                return None
        else:
            logger.error(f"Unexpected response from agent: {response}")
            return None

    # Set up the conversation retrieval chain
    def conversation_retrieval_chain(self, filter=None):
        # Ensure the vector database is used as a retriever
        contextualize_q_prompt = ChatPromptTemplate.from_messages([
            ("system", contextualize_q_system_prompt),
            MessagesPlaceholder("chat_history"),
            ("human", "{input}"),
        ])
        k_args = {"k": 3} if filter is None else {"k": 1, "filter": filter}
        retriever = self.vectordb.as_retriever(
            search_type="similarity",  # similarity / similarity_score_threshold / mmr
            search_kwargs=k_args # Retrieve top k relevant documents, larger k may lead to better context but slower response
        )
        history_aware_retriever = create_history_aware_retriever(
            self.llm_model, retriever, contextualize_q_prompt
        )
        qa_prompt = ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            MessagesPlaceholder("chat_history"),
            ("human", "{input}"),
        ])
        question_answer_chain = create_stuff_documents_chain(self.llm_model, qa_prompt)
        return create_retrieval_chain(history_aware_retriever, question_answer_chain)

    def chat(self, question):
        filter_agent_response = self.document_filter_agent(question, self.chat_history[-10:])
        logger.debug(f"Filter agent response: {filter_agent_response}")
        try:
            if filter_agent_response is None:
                rag_chain = self.conversation_retrieval_chain()
                response = rag_chain.invoke({
                    "input": question,
                    "chat_history": self.chat_history[-10:],  # Keep last 10 messages (5 exchanges)
                    "stream_number": filter_agent_response
                })
            else:
                rag_chain = self.conversation_retrieval_chain(filter={"tcp.stream": str(filter_agent_response)})
                response = rag_chain.invoke({
                "input": question,
                "chat_history": self.chat_history[-10:] # Keep last 10 messages (5 exchanges)
            })
            
            logger.debug(f"RAG chain response['input']: {response['input']}")
            logger.debug(f"RAG chain response['answer']: {response['answer']}")
            logger.debug(f"RAG chain response['chat_history']: {response.get('chat_history', 'N/A')}")
            logger.debug(f"RAG chain response['stream_number']: {response.get('stream_number', 'N/A')}")

            if response and "answer" in response:
                # Update chat history
                self.chat_history.extend([
                    HumanMessage(content=question),
                    AIMessage(content=response["answer"])
                ])
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
