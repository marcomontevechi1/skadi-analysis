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
                        default = False, action = 'store_true')
    parser.add_argument("--plot-adc-board", help="Plots pulseheight distribution for a given board. See also ", type=int)
    parser.add_argument("--bin-number", "-b", help="Bin number for any plotting.", type=int)
    parser.add_argument("--channel", "-c", help="Channel for plotting pulseHeight distribution.", type=int, default=None)
    parser.add_argument("--verbose", "-v", help="Talk about decoding progress", default=False, action = 'store_true')
    args = parser.parse_args()

    a = Analyzer(args.verbose, args.file)

    if args.print:
        a.print_packets(args.start, args.number, args.readouts)
    
    a.decode()
    if args.plot_packets:
        a.plot_arrival_times(bin_number=args.bin_number)
    if args.plot_adc_board is not None:
        a.plot_board_adc(args.plot_adc_board, args.bin_number, args.channel)

if __name__ == "__main__":
    main()

