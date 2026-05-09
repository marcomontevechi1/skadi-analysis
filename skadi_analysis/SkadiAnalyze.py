#!/usr/bin/env python3

from scapy.all import PcapReader
from argparse import ArgumentParser
from .GenericPacket import GenericPacket
from .Analyzer import Analyzer

def main():
    parser = ArgumentParser(description="Analyze PCAP files")
    parser.add_argument("--file", "-f", required=True, help="Path to the PCAP file to analyze")
    parser.add_argument("--number", "-n", type=int, default=None, 
                        help="Number of packets to print. (None for all)")
    parser.add_argument("--print", "-p", help="Print packet info. Default = false.", 
                        default=False, action = 'store_true')
    parser.add_argument("--start", "-s", type=int, default=0, 
                        help="Starting packet number (0 indexation).")
    parser.add_argument("--readouts", "-r", type=int, default=0, 
                        help="Number of readouts to print for each packet. (None for all)")
    parser.add_argument("--plot-packets", help="Plots number of packets and readout in time. Should have a bin number.",
                        default = None, type=int)
    args = parser.parse_args()

    a = Analyzer(args.file)

    if args.print:
        a.print_packets(args.start, args.number, args.readouts)
    if args.plot_packets is not None:
        a.decode()
        a.plot_arrival_times(bin_number=args.plot_packets)

if __name__ == "__main__":
    main()

