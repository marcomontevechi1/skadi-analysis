#!/usr/bin/env python3

from scapy.all import PcapReader
import numpy as np
import matplotlib.pyplot as plt

from .Board import Board
from .GenericPacket import GenericPacket

class Analyzer:

	"""
	Receives a list of pcap filenames, compile them into statistics.

	files: list of file names
	resolution for event per time histogram

	Variables in data:
		PacketTypes: number of packet for each type in total
		files: list of files analyzed
		ReadoutNUmber: list of number of readouts per packet
		PacketTimestamps: list of packet arrival times
	self.boards: dict of board objects. Should be dynamically filled by self.decode()
	"""

	def __init__(self, verbose = False, *files):

		self.data = {"PacketTypes": {"Non-17": 0, "Short-UDP": 0, "MDNS": 0, "Unknown": 0, "Skadi-RMM": 0},
			   		 "files": [], "ReadoutNumber": [], "PacketTimestamps": []}
		self.boards = dict()
		self.verbose = verbose

		for file in files:
			self.data["files"].append(file)

	def decode(self):
		"""
		Reads packet by packet, stored important info
		"""
		for file in self.data["files"]:
			with PcapReader(file) as pcap:
				packet_count = 0
				for packet in pcap:
					p = GenericPacket(packet)
					self.data["PacketTypes"][p.data["packet_type"]]+=1
					if p.data["packet_type"]!="Skadi-RMM":
						continue

					self.data["ReadoutNumber"].append(len(p.readouts))
					self.data["PacketTimestamps"].append(p.data["pkt_arrival_time"])
					for readout in p.readouts:
						if readout.data["IPLastOctet"] not in self.boards.keys():
							self.boards[readout.data["IPLastOctet"]] = Board(readout.data["IPLastOctet"])
						self.boards[readout.data["IPLastOctet"]].add_readout(readout)

					packet_count += 1
					if self.verbose:
						print(f"\rFinished decoding packet {packet_count}", end='', flush=True)

	def print_packets(self, start, number = None, readouts = 0):
		"""
		Prints n packets starting from packet number <start> (0 indexation)
		"""
		for file in self.data["files"]:
			with PcapReader(file) as pcap:
				packet_count = 0
				for packet in pcap:
					if number is not None and packet_count - start >= number:
						break
					if start is not None and packet_count < start:
						packet_count += 1
						continue
					p = GenericPacket(packet)
					p.pretty_print(readout_number=readouts)
					packet_count += 1
				print(f"Printed {packet_count} packets")

	def plot_arrival_times(self, bin_number = 100):
		fig, axs = plt.subplots(1, 2)
		axs[0].hist(self.data["PacketTimestamps"], bins = bin_number)
		axs[0].set_title("Packets per unix timestamp")

		#Now for readouts
		timestamps = np.array(self.data["PacketTimestamps"])
		readouts = np.array(self.data["ReadoutNumber"])
		bin_size = (timestamps.max() - timestamps.min())/bin_number
		bins = np.linspace(timestamps.min(), timestamps.max(), bin_number + 1)
		y, edges = np.histogram(self.data["PacketTimestamps"], bins=bins, weights=readouts)

		axs[1].bar(edges[:-1], y, width=bin_size, align='edge')
		axs[1].set_title("Readouts per unix timestamp")

		plt.show()

	def plot_board_adc(self, board, bin_number, channel = None):
		"""
		Calls plot_pulseheight for a given board and channel, with <bin_number> number of bins.
		"""
		self.boards[board].plot_pulseheight(bin_number, channel)