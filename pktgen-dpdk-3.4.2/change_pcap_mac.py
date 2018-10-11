#!/usr/bin/env python
# coding=utf-8

from scapy.utils import PcapReader, PcapWriter
from scapy.all import *
import sys

packet_count = 5000000

# pkt_reader = PcapReader(sys.argv[1])
pcap_reader = PcapReader("./p1p1.pcap")
pcap_writer = PcapWriter("./p1p1_500w.pcap")

for idx in range(packet_count):
    pkt = pcap_reader.read_packet()
    pkt[Ether].src = "68:91:D0:61:B4:C5"
    pkt[Ether].dst = "48:6E:73:00:04:DB"
    pcap_writer.write(pkt)
    if (idx + 1) % 10000 == 0:
        print("%d packet has been processed\n" % (idx + 1))

pcap_writer.flush()
pcap_writer.close()
