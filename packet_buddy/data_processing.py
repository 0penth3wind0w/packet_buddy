# Use pcap_to_json to convert pcap files to json
# Other functions to process the json data produced by pcap_to_json
# to either split the json into individual packet files, group packets by TCP stream,
# convert the json into a text file, or split the json into markdown files.
#
# Requires tshark to be installed


from typing import Literal
import subprocess
import os
import ijson
import json

FORMAT = Literal["json", "markdown", "txt"]

# Function to convert pcap to a single JSON
def pcap_to_json(pcap_path: str, json_path: str):
    command = f'tshark -nlr {pcap_path} -T json > {json_path}'
    subprocess.run(command, shell=True)

def split_by_packet(pcap_json: str, format: FORMAT):
    """
    Split a pcap file into individual packet files.
    
    Args:
        pcap_path (str): Path to the input pcap file.
        output_dir (str): Directory to save the output files.
        format: Format of the output files ('json' / 'markdown' / 'txt').
    """
    if format not in ["json", "markdown", "txt"]:
        raise ValueError("Format must be 'json', 'markdown', or 'txt'.")
    with open(pcap_json, 'r') as in_file:
        packets = ijson.items(in_file, 'item')
        for packet in packets:
            packet_data = packet.get("_source", {}).get('layers', {})
            frame = packet_data.get('frame', {})
            ip = packet_data.get('ip', {})
            tcp = packet_data.get('tcp', {})

            dir = os.path.dirname(pcap_json)
            if not os.path.exists(f"{dir}/{format}"):
                os.makedirs(f"{dir}/{format}")
            file_extension = f"{format}" if format != "markdown" else "md"

            with open(f"{dir}/{format}/frame_{frame['frame.number']}.{file_extension}", 'w') as outfile:
                frame_info = {
                    "tcp.stream": tcp.get('tcp.stream'),
                    "tcp.stream.pnum": tcp.get('tcp.stream.pnum'),
                    "frame.number": frame.get('frame.number'),
                    "frame.len": frame.get('frame.len'),
                    "frame.time_utc": frame.get('frame.time_utc'),
                    "ip.src": ip.get('ip.src'),
                    "ip.dst": ip.get('ip.dst'),
                    "tcp.srcport": tcp.get('tcp.srcport'),
                    "tcp.dstport": tcp.get('tcp.dstport'),
                }
                if tcp.get('tcp.payload'):
                    frame_info["tcp.payload"] = tcp.get('tcp.payload')
                if tcp.get('tcp.segment_data'):
                    frame_info["tcp.segment_data"] = tcp.get('tcp.segment_data')
                if format == "json":
                    json.dump(frame_info, outfile, indent=2)
                elif format == "markdown":
                    description = (
                        f"# Frame {frame['frame.number']}\n"
                        "## Capture time\n"
                        f"{frame['frame.time_utc']}\n"
                        "## Stream Information\n"
                        f"### Stream Number\n{tcp['tcp.stream']}\n"
                        f"### Stream Packet Number\n{tcp['tcp.stream.pnum']}\n"
                        "## Source\n"
                        f"### IP\n{ip['ip.src']}\n"
                        f"### Port\n{tcp['tcp.srcport']}\n"
                        "## Destination\n"
                        f"### IP\n{ip['ip.dst']}\n"
                        f"### Port\n{tcp['tcp.dstport']}\n"
                        f"{"## TCP Information\n" if tcp.get('tcp.payload') or tcp.get('tcp.segment_data') else ""}"
                        f"### Payload\n{tcp.get('tcp.payload')}\n" if tcp.get('tcp.payload') else ""
                        f"### Segment Data\n{tcp.get('tcp.segment_data')}\n" if tcp.get('tcp.segment_data') else ""
                        "\n"
                    )
                    outfile.write(description)
                elif format == "txt":
                    description = (
                        f"Frame {frame['frame.number']} was captured at {frame['frame.time_utc']}.\n"
                        f"It is the {tcp["tcp.stream.pnum"]} packet in the TCP stream {tcp['tcp.stream']}.\n"
                        f"The source IP and port is {ip['ip.src']}:{tcp['tcp.srcport']}, and the destination is {ip['ip.dst']}:{tcp['tcp.dstport']}.\n"
                        f"The TCP payload is \"{tcp.get('tcp.payload')}\"\n" if tcp.get('tcp.payload') else ""
                        f"The TCP segment data is \"{tcp.get('tcp.segment_data')}\"\n" if tcp.get('tcp.segment_data') else ""
                        "\n"
                    )
                    outfile.write(description)
                else:
                    print("Unsupported format. Please use 'json', 'markdown', or 'txt'.")

def split_by_stream(pcap_json: str, format: FORMAT):
    """
    Split a pcap file into individual TCP streams.
    
    Args:
        pcap_path (str): Path to the input pcap file.
        output_dir (str): Directory to save the output files.
        format: Format of the output files ('json' / 'markdown' / 'txt').
    """
    if format not in ["json", "markdown", "txt"]:
        raise ValueError("Format must be 'json', 'markdown', or 'txt'.")
    
    with open(pcap_json, 'r') as in_file:
        packets = ijson.items(in_file, 'item')
        grouped_packets = {}
        for packet in packets:
            packet_data = packet.get("_source", {}).get('layers', {})
            frame = packet_data.get('frame', {})
            ip = packet_data.get('ip', {})
            tcp = packet_data.get('tcp', {})
            stream_number = tcp.get('tcp.stream')
            if stream_number not in grouped_packets:
                grouped_packets[stream_number] = []
            packet_info = {
                "frame.number": frame.get('frame.number'),
                "frame.len": frame.get('frame.len'),
                "tcp.stream.pnum": tcp.get('tcp.stream.pnum'),
                "frame.time_utc": frame.get('frame.time_utc'),
                "ip.src": ip.get('ip.src'),
                "ip.dst": ip.get('ip.dst'),
                "tcp.srcport": tcp.get('tcp.srcport'),
                "tcp.dstport": tcp.get('tcp.dstport'),
            }
            payload = tcp.get('tcp.payload')
            segment_data = tcp.get('tcp.segment_data')
            if payload:
                packet_info["tcp.payload"] = payload
            if segment_data:
                packet_info["tcp.segment_data"] = segment_data
            grouped_packets[stream_number].append(packet_info)
        
        # write to file
        dir = os.path.dirname(pcap_json)
        if not os.path.exists(f"{dir}/{format}"):
            os.makedirs(f"{dir}/{format}")
        file_extension = f"{format}" if format != "markdown" else "md"

        for stream_number, frames in grouped_packets.items():
            with open(f"{dir}/{format}/stream_{stream_number}.{file_extension}", 'w') as outfile:
                if format == "json":
                    data = {
                        "tcp.stream": stream_number,
                        "frames": frames
                    }
                    json.dump(data, outfile, indent=2)
                elif format == "markdown":
                    outfile.write(f"# TCP Stream {stream_number}\n\n")
                    for frame in frames:
                        outfile.write(f"## Frame {frame['frame.number']}\n")
                        outfile.write(f"### Length\n{frame['frame.len']}\n")
                        outfile.write(f"### Stream Packet Number\n{frame['tcp.stream.pnum']}\n")
                        outfile.write(f"### Capture time\n{frame['frame.time_utc']}\n")
                        outfile.write(f"### Source IP and Port\n{frame['ip.src']}:{frame['tcp.srcport']}\n")
                        outfile.write(f"### Destination IP and Port\n{frame['ip.dst']}:{frame['tcp.dstport']}\n")
                        if frame.get('tcp.payload'):
                            outfile.write(f"### TCP Payload\n{frame['tcp.payload']}\n")
                        if frame.get('tcp.segment_data'):
                            outfile.write(f"### TCP Segment Data\n{frame['tcp.segment_data']}\n")
                        outfile.write("\n")
                elif format == "txt":
                    outfile.write(f"TCP Stream {stream_number}\n\n")
                    for frame in frames:
                        outfile.write(f"Frame {frame['frame.number']} was captured at {frame['frame.time_utc']}.\n")
                        outfile.write(f"It is the {frame['tcp.stream.pnum']} packet in the TCP stream {stream_number}.\n")
                        outfile.write(f"Source IP and port: {frame['ip.src']}:{frame['tcp.srcport']}, Destination IP and port: {frame['ip.dst']}:{frame['tcp.dstport']}\n")
                        if frame.get('tcp.payload'):
                            outfile.write(f"The TCP payload is \"{frame['tcp.payload']}\".\n")
                        if frame.get('tcp.segment_data'):
                            outfile.write(f"The TCP segment data is \"{frame['tcp.segment_data']}\".\n")
                        outfile.write("\n")

if __name__ == "__main__":
    PCAP_PATH = "packet_data/t.pcap"
    pcap_to_json(PCAP_PATH, f"{PCAP_PATH}.json")
    split_by_stream(f"{PCAP_PATH}.json", "txt")
    split_by_stream(f"{PCAP_PATH}.json", "markdown")
    split_by_stream(f"{PCAP_PATH}.json", "json")
    # split_by_packet(f"{PCAP_PATH}.json", "txt")
    # split_by_packet(f"{PCAP_PATH}.json", "markdown")
    # split_by_packet(f"{PCAP_PATH}.json", "json")

