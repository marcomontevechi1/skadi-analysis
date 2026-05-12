#!/usr/bin/env python3

from argparse import ArgumentParser
from .Analyzer import Analyzer


def main():
    parser = ArgumentParser(description="Analyze PCAP files")
    parser.add_argument(
        "--file", "-f", required=True, help="Path to the PCAP file to analyze"
    )
    parser.add_argument(
        "--number",
        "-n",
        type=int,
        default=None,
        help="Number of packets to print. (None for all)",
    )
    parser.add_argument(
        "--print-packets",
        "-p",
        help="Print packet info for each packet. Default = false.",
        default=False,
        action="store_true",
    )
    parser.add_argument(
        "--print-packets-stats",
        "-ps",
        help="Print packet statistics. Default = false.",
        default=False,
        action="store_true",
    )
    parser.add_argument(
        "--start",
        "-s",
        type=int,
        default=0,
        help="Starting packet number (0 indexation).",
    )
    parser.add_argument(
        "--readouts",
        "-r",
        type=int,
        default=0,
        help="Number of readouts to print for each packet. (None for all)",
    )
    parser.add_argument(
        "--plot-packets",
        help="Plots number of packets and readout in time. Should have a bin number.",
        default=False,
        action="store_true",
    )
    parser.add_argument(
        "--plot-adc-board",
        help="Plots pulseheight distribution for a given board. See also bin-size.",
        default=False,
        action="store_true",
    )
    parser.add_argument(
        "--bin-number", "-b", help="Bin number for timestamp plotting.", type=int
    )
    parser.add_argument(
        "--bin-size",
        help="Size of bin for ADC plotting. Bin number will be plotted automatically.",
        type=int,
        default=1,
    )
    parser.add_argument(
        "--channel",
        "-c",
        help="Channel for plotting pulseHeight distribution.",
        type=int,
        default=None,
    )
    parser.add_argument(
        "--verbose",
        "-v",
        help="Talk about decoding progress",
        default=False,
        action="store_true",
    )
    parser.add_argument(
        "--dump", "-d", help="Filename to dump info in", type=str, default=None
    )
    args = parser.parse_args()

    a = Analyzer(args.verbose, args.channel, args.bin_size, args.file)
    a.decode()

    if args.print_packets:
        a.print_packets(args.start, args.number, args.readouts)
    if args.plot_packets:
        a.decode_timestamps()
        a.plot_arrival_times(bin_number=args.bin_number)
    if args.plot_adc_board:
        a.plot_ADC_boards()
    if args.print_packets_stats:
        a.print_packets_stats()
    if args.dump is not None:
        a.dump_ADC_file(args.dump)


if __name__ == "__main__":
    main()
