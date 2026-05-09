#!/usr/bin/env python3

import matplotlib.pyplot as plt

from .Readout import Readout

class Board:

	def __init__(self, id):
		self.id = id
		self.readouts = []

	def add_readout(self, readout: Readout):
		self.readouts.append(readout)

	def plot_pulseheight(self, bin_number, channel = None):
		"""
		Plots a histogram of number of events per pulseheight for a given channel.
		If channel == None, plots for all channels, summed.

		bin_number: number of bins in histogram
		"""
		adcs = []
		for readout in self.readouts:
			if (channel == None) or readout.data["Channel"] == channel:
				adcs.append(readout.data["ADC"])

		plt.hist(adcs, bins = bin_number)
		plt.show()