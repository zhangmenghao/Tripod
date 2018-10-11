#!/usr/bin/env python
# coding=utf-8

from scapy.utils import PcapReader, PcapWriter
from scapy.all import *
import sys


filename = sys.argv[1]
print("Reading " + filename)

pkt_reader = PcapReader(filename)
# pcap_reader = PcapReader("./p1p1_500w.pcap")

count = 0

for p in pkt_reader:
    count = count + 1
    if count % 10000 == 0:
        print("Reading line " + str(count))

print("File " + filename + " has " + str(count) + " entries.")
