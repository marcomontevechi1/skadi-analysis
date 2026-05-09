#!/usr/bin/env python3

from scapy.all import PcapReader
import numpy as np
import matplotlib.pyplot as plt
import yaml

from .GenericPacket import GenericPacket

MAX_ADC_HEIGHT = 65535

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

	def plot_board_adc(self, board, bin_size, channel = None, dumpfile = None):
		"""
		Decodes packets, plots a histogram of ADCs with bins size of bin_size.
		Bin size is size of bins so that bin_number can be adjusted automatically accordingly.

		There are easier ways of doing this, but this is done in order to allow for
		opening big files without using all system's RAM.
		"""

		pkt_count = 0
		binned = np.zeros(MAX_ADC_HEIGHT//bin_size + 1, dtype=int)

		for file in self.data["files"]:

			with PcapReader(file) as pcap:

				for packet in pcap:
					p = GenericPacket(packet)
					if p.data["packet_type"]!="Skadi-RMM":
						continue

					for readout in p.readouts:
						octet = readout.data["IPLastOctet"]
						ch = readout.data["Channel"]
						if (board is None or board == octet) and (channel is None or channel == ch):
							binned[readout.data["ADC"]//bin_size]+=1
				
					pkt_count += 1
					if self.verbose:
						print(f"\rFinished decoding packet {pkt_count}", end='', flush=True)
		if self.verbose:
			print("")

		largest_nonzero_index = np.max(np.nonzero(binned))
		binned = binned[:largest_nonzero_index+1]
		edges = np.arange(len(binned) + 1) * bin_size

		if dumpfile is not None:
			data = {"Binned number of events": binned.tolist(), "edges": edges.tolist(), 
		   "Board": board, "Channel": channel, "Bin size": bin_size}
			with open(dumpfile, 'w') as file:
				file.write(yaml.dump(data))

		plt.stairs(binned, edges)
		plt.title("ADC PulseHeight distribution")
		plt.show()