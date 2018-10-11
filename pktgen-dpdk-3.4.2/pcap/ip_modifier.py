#!/usr/bin/env python
# coding=utf-8

from scapy.utils import PcapReader, PcapWriter
from scapy.all import *
import sys

packet_count = 50000

# pkt_reader = PcapReader(sys.argv[1])
pcap_reader = PcapReader("./p1p1_500w.pcap")
pcap_writer = PcapWriter("./p1p1_500w_rand_ip1.pcap")

for idx in range(0, 50):
    pkt = pcap_reader.read_packet()
#    print(type(pkt[IP].dst))
    pkt[IP].src = "0." + str((idx % 50) * 3)  + ".0." + str(idx)
    pkt[IP].dst = str((idx % 50) * 2) + ".0." + str(idx) + ".0"

#    print(pkt[TCP].sport, pkt[TCP].dport)
    pkt[TCP].sport = idx * 133
    pkt[TCP].dport = 65535 - 73 * idx
    pcap_writer.write(pkt)

for idx in range(50, packet_count):
    pkt = pcap_reader.read_packet()
    pkt[IP].src = "0." + str((idx % 50) * 3)  + ".0." + str(idx % 50)
    pkt[IP].dst = str((idx % 50) * 2) + ".0." + str(255 - idx % 50) + ".0"
    pkt[TCP].sport = (idx % 50) * 133
    pkt[TCP].dport = 65535 - 73 * (idx % 50)
    #  pkt[Ether].src = "68:91:D0:61:B4:C5"
    #  pkt[Ether].dst = "48:6E:73:00:04:DB"
    #  pkt[TCP].payload = "i" * (128 - 54)
    pcap_writer.write(pkt)
    if (idx + 1) % 10000 == 0:
        print("%d packet has been processed\n" % (idx + 1))

pcap_writer.flush()
pcap_writer.close()
