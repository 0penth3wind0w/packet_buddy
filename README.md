# packet_buddy
pcap analysis provided by Ollama and the open source model of your choice!

## How to use
You can either run the application with virtualenv or docker

### Run with virtualenv

#### Set Up
- Install `tshark`
- Create virtual environment `virtualenv venv`
- Install packages `pip install -r packet_buddy/requirements.txt`
- Get model with `ollama pull`
- Update [config.ini](./packet_buddy/config.ini) with the correct ollama url and models to be use with

#### Run
- Activate virtualenv `source venv/bin/activate`
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
2. Ask questions about the PCAP

## Tuning
You can select the appropriate models for your use case and hardware capabilities. Different models excel at different aspects of network analysis.
> The content of model specification is taken from response of Github Copilot with Claude Sonnet 4, some might not be correct

### Embedding model

- #### nomic-embed-text:latest
    - Excellent at capturing semantic relationships in structured data like network packets
    - Good at embedding protocol-specific terminology and technical concepts
    - Maintains relationship between related packets in connection flows
    - Preserves technical hierarchies (e.g., network layers, protocol relationships)
    - **Resource Usage**: ~380MB RAM, Fast inference speed
    - `ollama pull nomic-embed-text:latest`

- #### bge-m3:567m
    - Exceptional handling of hex-encoded payloads and binary data representations
    - Maintains coherence between related packets in the same connection
    - Excellent at capturing protocol-specific patterns and anomalies
    - Can effectively represent complex network hierarchies
    - **Resource Usage**: ~1.1GB RAM, Moderate inference speed
    - `ollama pull bge-m3:567m`

- #### all-minilm:l6-v2
    - Lightweight and efficient for basic packet analysis
    - Good for simple queries and pattern matching
    - Fast processing suitable for real-time analysis
    - Limited context understanding compared to larger models
    - **Resource Usage**: ~90MB RAM, Very fast inference speed 
    - `ollama pull all-minilm:l6-v2`


### Language Model

- #### mixtral:8x7b
    - Superior reasoning about complex network interactions
    - Excellent at explaining protocol behaviors and anomalies
    - Strong code generation and analysis capabilities
    - Can handle detailed technical questions about networking concepts
    - **Resource Usage**: ~26GB RAM, Slower inference but high quality
    - `ollama pull mixtral:8x7b`

- #### codellama:13b
    - Exceptional understanding of network protocols and structures
    - Superior ability to analyze packet patterns and anomalies
    - Strong at generating explanations of technical networking concepts
    - Excellent at writing code to process or analyze network data
    - **Resource Usage**: ~8GB RAM, Moderate inference speed

- #### llama3:8b
    - Well-balanced general knowledge including networking concepts
    - Good instruction following for analytical tasks
    - Reasonable code generation capabilities
    - Efficient balance of performance and resource usage
    - **Resource Usage**: ~4.7GB RAM, Good inference speed
    - `ollama pull llama3:8b`

- #### llama3.2:3b
    - Lightweight option for basic network analysis
    - Good for simple packet interpretation and basic queries
    - Fast response times suitable for interactive analysis
    - Limited deep technical analysis compared to larger models
    - **Resource Usage**: ~2GB RAM, Fast inference speed
    - `ollama pull llama3.2:3b`

- #### qwen2.5:14b
    - Excellent reasoning capabilities for complex network scenarios
    - Strong at correlating packets across different protocols
    - Good at identifying security patterns and anomalies
    - Balanced performance for detailed analysis tasks
    - **Resource Usage**: ~8.5GB RAM, Moderate inference speed
    - `ollama pull qwen2.5:14b`

- #### deepseek-coder:6.7b
    - Specialized in code analysis and generation for network tools
    - Excellent at creating custom packet analysis scripts
    - Strong understanding of networking libraries and APIs
    - Good for automated analysis workflow generation
    - **Resource Usage**: ~4GB RAM, Good inference speed 

### Recommended Combinations (by Copilot)

- #### For Resource-Constrained Environments
    - **Embedding**: `all-minilm:l6-v2`
    - **Language**: `llama3.2:3b`
    - **Use Case**: Basic packet analysis, simple queries, development/testing

- #### For Balanced Performance
    - **Embedding**: `nomic-embed-text:latest`
    - **Language**: `llama3:8b`
    - **Use Case**: General network analysis, education, moderate complexity queries

- #### For Advanced Analysis
    - **Embedding**: `bge-m3:567m`
    - **Language**: `qwen2.5:14b` or `codellama:13b`
    - **Use Case**: Security analysis, protocol research, complex network troubleshooting

- #### For Maximum Capability
    - **Embedding**: `bge-m3:567m`
    - **Language**: `mixtral:8x7b`
    - **Use Case**: Enterprise security analysis, research, complex multi-protocol investigations

## Attribution
Inspired and modified from [automateyournetwork/packet_buddy](https://github.com/automateyournetwork/packet_buddy)
