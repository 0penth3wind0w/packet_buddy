FROM ubuntu:latest

ARG DEBIAN_FRONTEND=noninteractive

# Upgrade apt and install packages
RUN apt -y update \
  && apt install -y wget \
  && apt install -y tshark \
  && apt install -y python3-full \
  && apt install -y python3-pip \
  && apt install -y python3-venv

# Create and activate Python venv
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY /packet_buddy /packet_buddy/
RUN pip install -r /packet_buddy/requirements.txt

WORKDIR /packet_buddy
CMD ["streamlit", "run", "packet_buddy.py"]
