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
                if format == "json":
                    packet_info = {
                        "frame": frame,
                        "ip": ip,
                        "tcp": tcp
                    }
                    json.dump(packet_info, outfile, indent=2)
                else:
                    tcp_payload = tcp.get('tcp.payload')
                    tcp_segment_data = tcp.get('tcp.segment_data')
                    try:
                        tcp_analysis_message = tcp.get('tcp.analysis', {}).get('tcp.analysis.flags', {}).get('_ws.expert', {}).get('_ws.expert.message')
                    except:
                        tcp_analysis_message = None
                    try:
                        if format == "markdown":
                            payload_description = f"### TCP payload\n{tcp_payload}\n" if tcp_payload else ""
                            segment_description = f"### TCP segment data\n{tcp_segment_data}\n" if tcp_segment_data else ""
                            analysis_message = f"> Note: {tcp_analysis_message}\n" if tcp_analysis_message else ""
                            tcp_info_header = "## TCP Information\n" if (tcp_payload or tcp_segment_data or tcp_analysis_message) else ""
                            description = (
                                f"# Frame {frame['frame.number']}\n"
                                "## Capture time\n"
                                f"{frame['frame.time_utc']}\n"
                                "## Stream Information\n"
                                f"### Stream Number: {tcp['tcp.stream']}\n"
                                f"### Stream Packet Number: {tcp['tcp.stream.pnum']}\n"
                                "## IP Information\n"
                                f"### Source IP: {ip['ip.src']}\n"
                                f"### Source Port: {tcp['tcp.srcport']}\n"
                                f"### Destination IP: {ip['ip.dst']}\n"
                                f"### Destination Port: {tcp['tcp.dstport']}\n"
                                f"{tcp_info_header}"
                                f"{payload_description}"
                                f"{segment_description}"
                                f"{analysis_message}"
                                "\n"
                            )
                        elif format == "txt":
                            payload_description = f"The TCP payload is \"{tcp_payload}\".\n" if tcp_payload else ""
                            segment_description = f"The TCP segment data is \"{tcp_segment_data}\".\n" if tcp_segment_data else ""
                            analysis_message = f"Note: {tcp_analysis_message}.\n" if tcp_analysis_message else ""
                            description = (
                                f"Frame {frame['frame.number']} was captured at {frame['frame.time_utc']}.\n"
                                f"It is the {tcp["tcp.stream.pnum"]} packet in the TCP stream {tcp['tcp.stream']}.\n"
                                f"The source IP and port is {ip['ip.src']}:{tcp['tcp.srcport']}, and the destination is {ip['ip.dst']}:{tcp['tcp.dstport']}.\n"
                                f"{payload_description}"
                                f"{segment_description}"
                                f"{analysis_message}"
                                "\n"
                            )
                        outfile.write(description)
                    except:
                        print(f"Error processing packet: {frame['frame.number']}")

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
            grouped_packets[stream_number].append({
                "frame.number": frame.get('frame.number'),
                "frame.time_utc": frame.get('frame.time_utc'),
                "ip.version": ip.get('ip.version'),
                "ip.src": ip.get('ip.src'),
                "ip.dst": ip.get('ip.dst'),
                "tcp.srcport": tcp.get('tcp.srcport'),
                "tcp.dstport": tcp.get('tcp.dstport'),
                "tcp.flags": tcp.get('tcp.flags'),
                "tcp.analysis": tcp.get('tcp.analysis'),
                "tcp.payload": tcp.get('tcp.payload'),
                "tcp.segment_data": tcp.get('tcp.segment_data')
            })
        
        # write to file
        dir = os.path.dirname(pcap_json)
        if not os.path.exists(f"{dir}/{format}"):
            os.makedirs(f"{dir}/{format}")
        file_extension = f"{format}" if format != "markdown" else "md"

        for stream_number, frames in grouped_packets.items():
            with open(f"{dir}/{format}/stream_{stream_number}.{file_extension}", 'w') as outfile:
                if format == "json":
                    data = {
                        "stream_number": stream_number,
                        "frames": frames
                    }
                    json.dump(data, outfile, indent=2)
                elif format == "markdown":
                    outfile.write(f"# TCP Stream {stream_number}\n\n")
                    for frame in frames:
                        outfile.write(f"## Frame {frame['frame.number']}\n")
                        outfile.write(f"### Capture time\n{frame['frame.time_utc']}\n")
                        outfile.write(f"### IP Version:\n{frame['ip.version']}\n")
                        outfile.write(f"### Source `IP:port`:\n{frame['ip.src']}:{frame['tcp.srcport']}\n")
                        outfile.write(f"### Destination `IP:port`:\n{frame['ip.dst']}:{frame['tcp.dstport']}\n")
                        if frame['tcp.payload']:
                            outfile.write(f"### TCP Payload:\n{frame['tcp.payload']}\n")
                        if frame['tcp.segment_data']:
                            outfile.write(f"### TCP Segment Data:\n{frame['tcp.segment_data']}\n")
                        if frame['tcp.analysis']:
                            analysis_flags = frame['tcp.analysis'].get('tcp.analysis.flags', {})
                            if analysis_flags:
                                outfile.write(f"> Note: {analysis_flags.get('_ws.expert.message', 'No analysis flags')}\n")
                        outfile.write("\n")
                elif format == "txt":
                    outfile.write(f"TCP Stream {stream_number}\n\n")
                    for frame in frames:
                        outfile.write(f"Frame {frame['frame.number']} was captured at {frame['frame.time_utc']}.\n")
                        outfile.write(f"IP Version: {frame['ip.version']}\n")
                        outfile.write(f"Source IP and port: {frame['ip.src']}:{frame['tcp.srcport']}, Destination IP and port: {frame['ip.dst']}:{frame['tcp.dstport']}\n")
                        if frame['tcp.payload']:
                            outfile.write(f"The TCP payload is \"{frame['tcp.payload']}\".\n")
                        if frame['tcp.segment_data']:
                            outfile.write(f"The TCP segment data is \"{frame['tcp.segment_data']}\".\n")
                        if frame['tcp.analysis']:
                            analysis_flags = frame['tcp.analysis'].get('tcp.analysis.flags', {})
                            if analysis_flags:
                                outfile.write(f"Note: {analysis_flags.get('_ws.expert.message', 'No analysis flags')}\n")
                        outfile.write("\n")

if __name__ == "__main__":
    PCAP_PATH = "packet_data/t.pcap"
    pcap_to_json(PCAP_PATH, f"{PCAP_PATH}.json")
    split_by_stream(f"{PCAP_PATH}.json", "txt")
    split_by_stream(f"{PCAP_PATH}.json", "markdown")
    split_by_stream(f"{PCAP_PATH}.json", "json")

