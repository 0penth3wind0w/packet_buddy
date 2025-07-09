import os
import subprocess
import streamlit as st
from configparser import ConfigParser
# https://python.langchain.com/api_reference/langchain/chains/langchain.chains.conversational_retrieval.base.ConversationalRetrievalChain.html
from langchain.chains import (
    create_history_aware_retriever,
    create_retrieval_chain,
)
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain_chroma import Chroma
from langchain_community.document_loaders import JSONLoader
from langchain_ollama import OllamaLLM, OllamaEmbeddings
from langchain_core.messages import HumanMessage, AIMessage

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
    You are a helper assistant specialized in analysing packet captures used for troubleshooting & technical analysis. 
    Use the following packet capture information to answer the user's question:

    {context}

    Based on the packet capture data above, provide a detailed analysis. If the user asks about a specific application layer protocol, use the following hints to inspect the packet_capture_info:

    hints :
    - http means tcp.port = 80
    - https means tcp.port = 443
    - snmp means udp.port = 161 or udp.port = 162
    - ntp means udp.port = 123
    - ftp means tcp.port = 21
    - ssh means tcp.port = 22
    - BGP means tcp.port = 179
    - OSPF uses IP protocol 89 (not TCP/UDP port-based, but rather directly on top of IP)
    - DNS means udp.port = 53 (also tcp.port = 53)
    - DHCP uses udp.port = 67 (server) and udp.port = 68 (client)
    - SMTP means tcp.port = 25 (for email sending)
    - POP3 means tcp.port = 110 (for email retrieval)
    - IMAP means tcp.port = 143 (for email retrieval, with more features than POP3)
    - LDAP means tcp.port = 389 (for accessing and maintaining distributed directory information services over an IP network)
    - LDAPS means tcp.port = 636 (secure version of LDAP)
    - SIP means tcp.port = 5060 or udp.port = 5060 (for initiating interactive user sessions involving multimedia elements such as video, voice, chat, gaming, etc.)
    - RTP (Real-time Transport Protocol) doesn't have a fixed port but is commonly used in conjunction with SIP for the actual data transfer of audio and video streams.

    Format your response in markdown with line breaks and emojis. Always reference specific packet data when possible.
"""

# Define a class for chatting with pcap data
class ChatWithPCAP:
    def __init__(self, json_path):
        self.embedding_model = OllamaEmbeddings(model=EMBEDDING_MODEL)
        self.json_path = json_path
        self.load_json()
        self.store_in_chroma()
        self.chat_history = []
        self.setup_conversation_retrieval_chain()

    def load_json(self):
        self.loader = JSONLoader(file_path=self.json_path, jq_schema=".[] | ._source.layers", text_content=False)
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
            search_kwargs={"k": 15} # Retrieve top k relevant documents, larger k may lead to better context but slower response
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
        question_answer_chain = create_stuff_documents_chain(self.llm, qa_prompt)
        self.rag_chain = create_retrieval_chain(history_aware_retriever, question_answer_chain)

    def chat(self, question):
        try:
            response = self.rag_chain.invoke({
                "input": question,
                "chat_history": self.chat_history[-10:] # Keep last 5 exchanges (10 messages)
            })

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

# Function to convert pcap to JSON
def pcap_to_json(pcap_path, json_path):
    command = f'tshark -nlr {pcap_path} -T json > {json_path}'
    subprocess.run(command, shell=True)

# Streamlit UI for uploading and converting pcap file
def upload_and_convert_pcap():
    st.title('Packet Buddy - Chat with pcap')
    uploaded_file = st.file_uploader("Choose a PCAP file", type="pcap")

    if uploaded_file:
        if not os.path.exists('packet_data'):
            os.makedirs('packet_data')
        pcap_path = os.path.join("packet_data", uploaded_file.name)
        json_path = pcap_path + ".json"

        with open(pcap_path, "wb") as f:
            f.write(uploaded_file.getvalue())

        pcap_to_json(pcap_path, json_path)
        st.session_state['json_path'] = json_path
        st.success("PCAP file uploaded and converted to JSON.")
        if st.button("Proceed to Chat"):
            st.session_state['page'] = 2
            st.rerun()

# Streamlit UI for chat interface
def chat_interface():
    st.title('Packet Buddy - Chat with pcap')
    
    json_path = st.session_state.get('json_path')
    if not json_path or not os.path.exists(json_path):
        st.error("PCAP file missing or not converted. Please go back and upload a PCAP file.")
        return

    with st.sidebar:
        if st.button("Clear Chat History"):
            st.session_state['chat_instance'].chat_history = []
            st.rerun()    
        st.button("Upload New PCAP", on_click=lambda: setattr(st.session_state, 'page', 1))

    if 'chat_instance' not in st.session_state:
        st.session_state['chat_instance'] = ChatWithPCAP(json_path=json_path)
    
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
