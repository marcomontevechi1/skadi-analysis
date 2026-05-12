#!/usr/bin/env python3

from scapy.all import PcapReader
import numpy as np
import matplotlib.pyplot as plt
import yaml

from .GenericPacket import GenericPacket
from .Readout import Readout

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
		for p in self.iterate_packets():
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

	def plot_board_adc(self, bin_size, channel = None, dumpfile = None):
		"""
		Decodes packets, plots a histogram of ADCs with bins size of bin_size.
		Bin size is size of bins so that bin_number can be adjusted automatically accordingly.

		There are easier ways of doing this, but this is done in order to allow for
		opening big files without using all system's RAM.
		"""

		pkt_count = 0
		boards = dict() #board[boardidx] = chan. chan[idx] = binned.
		packet_info = {"OM1": 0, "OM2": 0, "OM3": 0, "Non-17": 0,
				 	   "Short-UDP": 0, "MDNS": 0, "Unknown": 0, "Skadi-RMM": 0}

		for evt_type in Readout.EVENT_TYPES.values():
			packet_info[evt_type] = 0
		for evt_type in Readout.EVENT_TYPES_OM0.values():
			packet_info[evt_type] = 0

		for p in self.iterate_packets():
			packet_info[p.data["packet_type"]]+=1
			if p.data["packet_type"]!="Skadi-RMM":
				continue

			for readout in p.readouts:
				packet_info[readout.data["EvtType"]]+=1
				packet_info[f"OM{readout.data['OM']}"]+=1

				octet = readout.data["IPLastOctet"]
				ch = readout.data["Channel"]
				if octet not in boards.keys():
					boards[octet] = np.zeros((256, MAX_ADC_HEIGHT//bin_size + 1), dtype=int)
				boards[octet][ch][readout.data["ADC"]//bin_size]+=1
		
			pkt_count += 1
			if self.verbose:
				print(f"\rFinished decoding packet {pkt_count}", end='', flush=True)
				
		if self.verbose:
			print("")

		if channel is None:
			for octet in boards.keys():
				boards[octet] = np.sum(boards[octet], axis=0)
		else:
			for octet in boards.keys():
				boards[octet] = boards[octet][channel]

		print("Packets info:")
		print(yaml.dump(packet_info, allow_unicode=True, default_flow_style=False))
		self.plot_ADC_boards(boards, bin_size)
		boards["Bin size"] = bin_size
		boards["Channel"] = channel
		boards["Files"] = self.data["files"]
		self.dump_ADC_file(dict(boards, **packet_info), dumpfile)

	def plot_ADC_boards(self, boards, bin_size):
		fig, ax = plt.subplots(len(boards.keys())//4 + 1, 4)
		for i, octet in enumerate(sorted(boards)):
			row = i//4
			col = i%4
			largest_nonzero_index = np.max(np.nonzero(boards[octet]))
			binned = boards[octet][:largest_nonzero_index+1]
			edges = np.arange(len(binned) + 1) * bin_size
			ax[row][col].stairs(binned, edges)
			ax[row][col].set_title(f"Board {octet}")
		plt.suptitle("ADC PulseHeight distribution")
		plt.show()

	def dump_ADC_file(self, boards, filename):
		if filename is not None:
			if self.verbose:
				print(f"Dumping data to {filename}...")
			for key in boards.keys():
				if isinstance(boards[key],np.ndarray):

					boards[key] = boards[key].tolist()
			with open(filename, 'w') as file:
				file.write(yaml.dump(boards))
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