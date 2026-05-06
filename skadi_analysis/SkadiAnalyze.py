#!/usr/bin/env python3

from scapy.all import PcapReader, ls
from argparse import ArgumentParser
from .GenericPacket import GenericPacket


def main():
    parser = ArgumentParser(description="Analyze PCAP files")
    parser.add_argument("--file", "-f", required=True, help="Path to the PCAP file to analyze")
    parser.add_argument("--number", "-n", type=int, default=None, 
                        help="Number of packets to read. (None for all)")
    parser.add_argument("--start", "-s", type=int, default=0, 
                        help="Starting packet number (0 indexation).")
    parser.add_argument("--readouts", "-r", type=int, default=0, 
                        help="Number of readouts to print for each packet. (None for all)")
    args = parser.parse_args()

    packet_count = 0
    with PcapReader(args.file) as pcap:
        for packet in pcap:
            if args.number is not None and packet_count - args.start >= args.number:
                break
            if args.start is not None and packet_count < args.start:
                packet_count += 1
                continue
            p = GenericPacket(packet)
            p.pretty_print(readout_number=args.readouts)
            packet_count += 1
        print(f"Analyzed {packet_count} packets")

if __name__ == "__main__":
    main()

