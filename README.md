# packet_buddy
pcap analysis provided by Ollama and the open source model of your choice!

## How to use
You can either run the application with virtualenv or docker

### Run with virtualenv

#### Set Up
- Install `tshark`
- Create virtual environment `virtualenv venv`
- Install packages `pip install -r packet_buddy/requirements.txt`
- Get desired model with `ollama pull`

#### Run
- Activate virtualenv `virtualenv venv`
- Start Ollama on host
- `cd packet_buddy`
- `streamlit run packet_buddy.py`
- Connect to `http://localhost:8505`

### Runs with Docker

#### Set Up
- Get desired model with `ollama pull`

#### Run
- Start Ollama on host
- `docker-compose up`
- Connect to `http://localhost:8505`

### Usage
1. Upload your PCAP 
2. Pick Model
3. Ask questions about the PCAP

## Attribution
Inspired and modified from [automateyournetwork/packet_buddy](https://github.com/automateyournetwork/packet_buddy)
