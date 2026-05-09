#!/usr/bin/env python3

from operator import add
import yaml

class Readout:
	"""A class to process and analyze specific readout data from Skadi"""

	HEADER_SIZE = 16
	OPERATION_MODES = ["TRIGGER TIME", "SINGLE PULSE-HEIGHT", "MULTIPLE PULSE-HEIGHT"]
	EVENT_TYPES = {1: "Software trigger (user)", 2: "ASIC trigger (real evt)", 
				   3: "Calibration trigger", 4: "External trigger",
				   5: "Single channel trigger", 6: "XA Multi trigger",
				   0: "systemclock auto-trigger"}
	EVENT_TYPES_OM0 = {0: "SyncEvent, normal event", 1: "SyncEvent, too late", 2: "SyncEvent, too early", 3: "SyncEvent, received"}

	def __init__(self, raw_data, number):
		"""
		Initialize Readout with specific data.

		Args:
		    data: bytes object with raw data. They can have more than needed,
				the object will only get what it needs and throw away the rest.
		    number: readout number
		"""
		self.data = dict()

		self.data["ReadoutNumber"] = number
		self.data["RingID"] = raw_data[0]
		self.data["FENID"] = raw_data[1]
		self.data["DataLength"] = int.from_bytes(raw_data[2:4], byteorder='little')

		raw_data = raw_data[0:self.HEADER_SIZE + self.data["DataLength"]] # Throw away what it doesn't need

		self.data["ESSTimestamp (s)"] = int.from_bytes(raw_data[4:8], byteorder='little')
		self.data["ESSTimestamp (clk)"] = int.from_bytes(raw_data[8:12], byteorder='little')
		self.data["OM"] = (raw_data[12] & 0xf0) >> 4
		self.data["Flags"] = (raw_data[12] & 0x0f)
		if self.data["OM"] == 0:
			self.data["EvtType"] = self.EVENT_TYPES_OM0[self.data["Flags"]]
		else:
			self.data["EvtType"] = self.EVENT_TYPES[self.data["Flags"]]
		self.data["SysID"] = raw_data[13]
		self.data["IPLastOctet"] = raw_data[14]
		self.data["Channel"] = raw_data[15]
		self.data["Column"] = raw_data[16]
		self.data["Row"] = int.from_bytes(raw_data[17:18])
		self.data["ADC"] = int.from_bytes(raw_data[18:20], byteorder="little")

	def pretty_print(self):
		print(f"Readout Data {self.data['ReadoutNumber']}")
		out = yaml.dump(self.data, allow_unicode=True, default_flow_style=False).rstrip('\n')
		print('\t' + out.replace('\n', '\n\t'))