#!/usr/bin/env python3

import struct
import socket
import yaml

from .Readout import Readout

START_HDR_SIZE = 74

class GenericPacket:
	"""A class to process and analyze packets from PcapReader."""
	resolution = 11.35686096363
	maxdatasize = 16 + 20

	def __init__(self, packet):
		"""
		Initialize GenericPacket with a packet from PcapReader.

		Args:
		    packet: A packet object from scapy.all.PcapReader
		"""
		self.packet = packet
		self.data = dict()
		self.readouts = []
		self.raw_data = bytes(packet)
		self.data["flags"] = f"0x{self.raw_data[20:22].hex()}"
		self.data["protocol"] = int.from_bytes(self.raw_data[23:24])

		if self.data["protocol"] != 17:
			self.data["packet_type"] = "Non-17"
			return

		self.data["src_addr"] = f"{'.'.join(str(b) for b in self.raw_data[26:30])}"
		self.data["dst_addr"] = f"{'.'.join(str(b) for b in self.raw_data[30:34])}"
		self.data["src_port"] = int.from_bytes(self.raw_data[34:36])
		self.data["dst_port"] = int.from_bytes(self.raw_data[36:38])
		self.data["UDP length"] = int.from_bytes(self.raw_data[38:40], byteorder="big")

		"""
		Next line introduces corner case. Maybe there is a better way to do it?
		"""
		if self.data["UDP length"] <= 55:
			self.data["packet_type"] = "Short-UDP"
			return
		if self.data["dst_port"] == 5353 and self.data["dst_addr"].split(".")[-1] == "251":
			self.data["packet_type"] = "MDNS"
			return

		self.data["padding"] = f"0x{self.raw_data[42:43].hex()}"
		self.data["version"] = int.from_bytes(self.raw_data[43:44])
		self.data["cookie"] = self.raw_data[44:47].decode()

		if self.data["cookie"] != "ESS":
			self.data["packet_type"] = "Unknown"
			return

		self.data["packet_type"] = "Skadi-RMM"
		self.data["detector_type"] = f"0x{self.raw_data[47:48].hex()}"
		self.data["length"] = int.from_bytes(self.raw_data[48:50][::-1])
		self.data["output_queue"] = int.from_bytes(self.raw_data[50:51])
		self.data["time_src"] = self.raw_data[51]
		self.data["PT"] = {"seconds": int.from_bytes(self.raw_data[52:56][::-1]), "nanoseconds": self.resolution * int.from_bytes(self.raw_data[56:60][::-1])}
		self.data["PrevPT"] = {"seconds": int.from_bytes(self.raw_data[60:64][::-1]), "nanoseconds": self.resolution * int.from_bytes(self.raw_data[64:68][::-1])}
		self.data["sequence_number"] = f"0x{self.raw_data[68:72][::-1].hex()}"
		
		position = 0
		while position < len(self.raw_data) - START_HDR_SIZE:
			try:
				self.readouts.append(Readout(self.raw_data[START_HDR_SIZE + position:START_HDR_SIZE + position + self.maxdatasize], len(self.readouts) + 1))
			except Exception as e:
				print(f"Error occurred while processing readout in SeqNo {self.data["sequence_number"]} at position {position}: {e}")
				break
			position += self.readouts[-1].data["DataLength"]

	def pretty_print(self, readout_number = None):
		print("Generic Packet")
		print(yaml.dump(self.data, allow_unicode=True, default_flow_style=False))
		print(f"{len(self.readouts)} Readouts.")
		for readout in self.readouts[:readout_number] if readout_number is not None else self.readouts:
			readout.pretty_print()