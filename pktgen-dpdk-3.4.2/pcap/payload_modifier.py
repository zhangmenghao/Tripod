#!/usr/bin/env python
# coding=utf-8

from scapy.utils import PcapReader, PcapWriter
from scapy.all import *
import sys

packet_count = 800000

readin_filename = str(sys.argv[1])
packet_size = int(sys.argv[2])

out_filename = readin_filename[:-5] + "_" + str(packet_size) + "b.pcap"

print("Reading pcap file: " + readin_filename)
print("Output to file: " + out_filename)
print("Target packet_size: " + str(packet_size) + "bytes")

pcap_reader = PcapReader(readin_filename)
pcap_writer = PcapWriter(out_filename)


for idx in range(packet_count):
    pkt = pcap_reader.read_packet()
    pkt[TCP].payload = "i" * (packet_size - 54)
    pcap_writer.write(pkt)
    if (idx + 1) % 10000 == 0:
        print("%d packet has been processed\n" % (idx + 1))

pcap_writer.flush()
pcap_writer.close()
