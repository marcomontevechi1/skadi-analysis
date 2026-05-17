#!/usr/bin/env python3

from scapy.all import PcapReader
import numpy as np
import matplotlib.pyplot as plt
from enum import StrEnum
import yaml

from .GenericPacket import GenericPacket
from .Readout import Readout

MAX_ADC_HEIGHT = 65535


class PossiblePlots(StrEnum):
    ADC = "ADC"
    EVENTS = "Events"


class Analyzer:
    """
    Receives a list of pcap filenames, compile them into statistics.

    Due to the files being big, most of the functions decode in execution time and store only what they
    must in memory. This is slow, but we are limited in RAM so...

    files: list of file names
    resolution for event per time histogram

    Variables in data:
            PacketTypes: number of packet for each type in total
            files: list of files analyzed
            ReadoutNUmber: list of number of readouts per packet
            PacketTimestamps: list of packet arrival times
    self.boards: dict of board objects. Should be dynamically filled by self.decode()
                             self.boards[octet]["ADC Bins"][channel][bin] = number of events in that bin.
                             self.boards[octet]["NumEvents"][channel][OperationMode] = number of events
                             for that channel, that operation mode.
    """

    def __init__(
        self,
        verbose=False,
        channel=None,
        bin_size=None,
        save_plots=None,
        low_events=None,
        low_events_threshold=10,
        *files,
    ):
        self.data = {
            "PacketTypes": {
                "Non-17": 0,
                "Short-UDP": 0,
                "MDNS": 0,
                "Unknown": 0,
                "Skadi-RMM": 0,
            },
            "files": [],
            "ReadoutNumber": [],
            "PacketTimestamps": [],
        }  # Should be deprecated in favor of self.packets_stats

        self.boards = dict()
        self.packets_stats = {
            "OM0": 0,
            "OM1": 0,
            "OM2": 0,
            "Non-17": 0,
            "Short-UDP": 0,
            "MDNS": 0,
            "Unknown": 0,
            "Skadi-RMM": 0,
        }
        self.analyzer = {"BinSize": bin_size, "Files": list(files)}
        for evt_type in Readout.EVENT_TYPES.values():
            self.packets_stats[evt_type] = 0
        for evt_type in Readout.EVENT_TYPES_OM0.values():
            self.packets_stats[evt_type] = 0

        self.verbose = verbose
        self.channel = channel
        self.bin_size = bin_size
        self.save_plots = save_plots
        self.low_events = low_events
        self.low_events_threshold = low_events_threshold

        for file in files:
            self.data["files"].append(file)

    def decode_timestamps(self):  # Should be deprecated soon
        """
        Reads packet by packet, stored important info
        """
        packet_count = 0
        for p in self.iterate_packets():
            self.data["PacketTypes"][p.data["packet_type"]] += 1
            if p.data["packet_type"] != "Skadi-RMM":
                continue

            self.data["ReadoutNumber"].append(len(p.readouts))
            self.data["PacketTimestamps"].append(p.data["pkt_arrival_time"])

            packet_count += 1
            if self.verbose:
                print(f"\rFinished decoding packet {packet_count}", end="", flush=True)

    def print_packets(self, start, number=None, readouts=0):
        """
        Prints n packets starting from packet number <start> (0 indexation)
        """
        packet_count = 0
        for packet in self.iterate_packets():
            if number is not None and packet_count - start >= number:
                break
            if start is not None and packet_count < start:
                packet_count += 1
                continue
            packet.pretty_print(readout_number=readouts)
            packet_count += 1
        print(f"Printed {packet_count} packets")

    def plot_arrival_times(self, bin_number=100):
        fig, axs = plt.subplots(1, 2)
        axs[0].hist(self.data["PacketTimestamps"], bins=bin_number)
        axs[0].set_title("Packets per unix timestamp")

        # Now for readouts
        timestamps = np.array(self.data["PacketTimestamps"])
        readouts = np.array(self.data["ReadoutNumber"])
        bin_size = (timestamps.max() - timestamps.min()) / bin_number
        bins = np.linspace(timestamps.min(), timestamps.max(), bin_number + 1)
        y, edges = np.histogram(
            self.data["PacketTimestamps"], bins=bins, weights=readouts
        )

        axs[1].bar(edges[:-1], y, width=bin_size, align="edge")
        axs[1].set_title("Readouts per unix timestamp")

        if self.save_plots is not None:
            if self.verbose:
                print(f"Saving plot file {self.save_plots}")
            fig.savefig(self.save_plots)

        plt.show()

    def decode(self):
        """
        Decodes packets, stores ADC values in binned containers.
        Bin size is size of bins so that bin_number can be adjusted automatically accordingly.

        There are easier ways of doing this, but this is done in order to allow for
        opening big files without using all system's RAM.
        """

        pkt_count = 0

        for p in self.iterate_packets():
            self.packets_stats[p.data["packet_type"]] += 1
            if p.data["packet_type"] != "Skadi-RMM":
                continue

            for readout in p.readouts:
                self.packets_stats[readout.data["EvtType"]] += 1
                self.packets_stats[f"OM{readout.data['OM']}"] += 1

                octet = readout.data["IPLastOctet"]
                ch = readout.data["Channel"]
                if octet not in self.boards.keys():
                    self.boards[octet] = {
                        "ADC Bins": np.zeros(
                            (256, MAX_ADC_HEIGHT // self.bin_size + 1), dtype=int
                        ),
                        "NumEvents": np.zeros((256, 3), dtype=int),
                    }
                self.boards[octet]["ADC Bins"][ch][
                    readout.data["ADC"] // self.bin_size
                ] += 1
                if readout.data["EvtType"] == "SyncEvent, normal event":
                    self.boards[octet]["NumEvents"][ch][readout.data["OM"]] += 1

            pkt_count += 1
            if self.verbose:
                print(f"\rFinished decoding packet {pkt_count}", end="", flush=True)

        if self.verbose:
            print("")

    def print_packets_stats(self):
        print("Packets stats:")
        print(
            yaml.dump(self.packets_stats, allow_unicode=True, default_flow_style=False)
        )

    def plot_ADC_boards(self):
        to_plot = self.get_to_plot(PossiblePlots.ADC)

        fig, ax = plt.subplots(len(to_plot.keys()) // 4 + 1, 4)
        for i, octet in enumerate(sorted(to_plot)):
            row = i // 4
            col = i % 4
            largest_nonzero_index = np.max(np.nonzero(to_plot[octet]))
            binned = to_plot[octet][: largest_nonzero_index + 1]
            edges = np.arange(len(binned) + 1) * self.bin_size
            ax[row][col].stairs(binned, edges)
            ax[row][col].set_title(f"Board {octet}")
        plt.suptitle("ADC PulseHeight distribution")

        if self.save_plots is not None:
            if self.verbose:
                print(f"Saving plot file {self.save_plots}")
            fig.savefig(self.save_plots)

        plt.show()

    def plot_events(self):
        """
        For each board, plot the number of events per channel, per operation mode
        and sum of total events
        """
        to_plot = self.get_to_plot(PossiblePlots.EVENTS)
        fig, ax = plt.subplots(len(to_plot.keys()) // 4 + 1, 4, constrained_layout=True)
        for i, octet in enumerate(sorted(to_plot)):
            row = i // 4
            col = i % 4
            current_ax = ax[row][col]
            current_ax.set_title(f"Board {octet}")
            current_ax.set_xlabel("Channel")
            current_ax.set_ylabel("Number of events")
            current_ax.plot(
                to_plot[octet].sum(axis=1), label="Total events", color="red"
            )
            current_ax.plot(
                range(0, 256), to_plot[octet][:, 0], label="OM0", color="blue"
            )
            current_ax.plot(
                range(0, 256), to_plot[octet][:, 1], label="OM1", color="green"
            )
            current_ax.plot(
                range(0, 256), to_plot[octet][:, 2], label="OM2", color="orange"
            )

        handles, labels = current_ax.get_legend_handles_labels()
        fig.legend(handles, labels, loc="upper left", ncol=4)

        if self.save_plots is not None:
            if self.verbose:
                print(f"Saving plot file {self.save_plots}")
            fig.savefig(self.save_plots, bbox_inches="tight")

        plt.show()

    def dump_low_events(self, low=10):
        """
        Dumps a yaml file listing which channels have less than <low> events.
        """
        low_events = dict()
        for octet in self.boards.keys():
            low_events[octet] = []
            for channel in range(256):
                if self.boards[octet]["NumEvents"][channel].sum() < low:
                    low_events[octet].append(channel)
        with open(self.low_events, "w") as file:
            file.write(yaml.dump(low_events))

    def get_to_plot(self, plot_type: PossiblePlots):
        to_plot = dict()
        if self.channel is None:
            for octet in self.boards.keys():
                if plot_type == PossiblePlots.ADC:
                    to_plot[octet] = np.sum(self.boards[octet]["ADC Bins"], axis=0)
                elif plot_type == PossiblePlots.EVENTS:
                    to_plot[octet] = self.boards[octet]["NumEvents"]
                else:
                    raise ValueError(f"Unknown plot type {plot_type}")
        else:
            for octet in self.boards.keys():
                if plot_type == PossiblePlots.ADC:
                    to_plot[octet] = self.boards[octet]["ADC Bins"][self.channel]
                elif plot_type == PossiblePlots.EVENTS:
                    to_plot[octet] = self.boards[octet]["NumEvents"][self.channel]
                else:
                    raise ValueError(f"Unknown plot type {plot_type}")
        return to_plot

    def dump_file(self, filename):
        data_to_dump = self.boards | self.packets_stats | self.analyzer
        if filename is not None:
            if self.verbose:
                print("Converting numpy arrays to lists...")
            recurse_tolist(data_to_dump)
            if self.verbose:
                print(f"Dumping data to file {filename}")
            with open(filename, "w") as file:
                file.write(yaml.dump(data_to_dump))
            if self.verbose:
                print("Dumped data successfully.")

    def iterate_packets(self):
        """
        Generator that iterates through all packets in all files, yielding a GenericPacket object.
        """
        for file in self.data["files"]:
            with PcapReader(file) as pcap:
                for packet in pcap:
                    yield GenericPacket(packet)


def recurse_tolist(dic: dict):
    """
    Recurses through a dictionary trnasforming every
    numpy array in its values into a list.
    """
    for key in dic.keys():
        if isinstance(dic[key], dict):
            recurse_tolist(dic[key])
        elif isinstance(dic[key], np.ndarray):
            dic[key] = dic[key].tolist()
