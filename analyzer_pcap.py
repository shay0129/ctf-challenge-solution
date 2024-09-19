from scapy.all import *
import argparse
from scapy.layers.inet import TCP, IP
from scapy.utils import rdpcap

def is_tls_packet(packet):
    return TCP in packet and (packet[TCP].dport == 443 or packet[TCP].sport == 443)

def filter_packets(pcap_file, filter_ip, start_frame, end_frame):
    # Filter is: (ip.dst == 193.34.188.81 or ip.src == 193.34.188.81) and tls and frame.number > 65 and frame.number < 96
    packets = rdpcap(pcap_file)
    filtered_packets = []

    for i, packet in enumerate(packets, 1):
        if (start_frame < i < end_frame and
            IP in packet and
            (packet[IP].src == filter_ip or packet[IP].dst == filter_ip) and
            is_tls_packet(packet)):
            filtered_packets.append((i, packet))

    return filtered_packets

def get_tls_info(frame_number, tcp_len):
    if frame_number == 66:
        return "Client Hello (SNI=www.hattrick.org)"
    elif frame_number == 70:
        return "Server Hello, Certificate, Server Key Exchange, Server Hello Done"
    elif frame_number == 71:
        return "Client Key Exchange, Change Cipher Spec, Encrypted Handshake Message"
    elif frame_number in [86, 87]:
        return "Change Cipher Spec, Encrypted Handshake Message"
    elif tcp_len > 0:
        return "Application Data"
    else:
        return ""

def print_packet_summary(packets):
    print("No.\tSource\t\tDestination\tProtocol\tTCP Segment Len\tAcknowledgment Number\tSequence Number\tInfo")
    for frame_number, packet in packets:
        if frame_number in [66, 70, 71, 86, 87, 94, 95]:  # Only print specific frames
            ip = packet[IP]
            tcp = packet[TCP]
            tcp_len = len(tcp.payload)
            tls_info = get_tls_info(frame_number, tcp_len)
            print(f"{frame_number}\t{ip.src}\t{ip.dst}\tTLSv1.2\t\t{tcp_len}\t\t{tcp.ack}\t\t{tcp.seq}\t{tls_info}")

def main():
    parser = argparse.ArgumentParser(description="Filter PCAP for TLS packets with specific IP and frame numbers")
    parser.add_argument("pcap_file", help="Path to the PCAP file")
    parser.add_argument("--ip", default="193.34.188.81", help="IP address to filter (default: 193.34.188.81)")
    parser.add_argument("--start", type=int, default=65, help="Start frame number (default: 65)")
    parser.add_argument("--end", type=int, default=96, help="End frame number (default: 96)")
    args = parser.parse_args()

    try:
        filtered_packets = filter_packets(args.pcap_file, args.ip, args.start, args.end)
        print(f"Found {len(filtered_packets)} packets matching the filter.")
        print_packet_summary(filtered_packets)
    except FileNotFoundError:
        print(f"Error: The file '{args.pcap_file}' was not found.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()

# python analyzer_pcap.py TLSsniffEx.pcapng