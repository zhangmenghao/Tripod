#!/usr/bin/env python
# coding=utf-8

from scapy.utils import PcapReader, PcapWriter
from scapy.all import *
import random
import sys

packet_count = 100000
flow_count = 50
packet_size = 64
ip_src_array = []
ip_dst_array = []
port_src_array = []
port_dst_array = []

# pkt_reader = PcapReader(sys.argv[1])
pcap_reader = PcapReader("../../client.pcap")
pcap_writer = PcapWriter("./flow1w.pcap")

for idx in range(flow_count):
    ip_src = "%d.%d.%d.%d" % (
        random.randint(0, 255), random.randint(0, 255),
        random.randint(0, 255), random.randint(0, 255)
    )
    ip_dst = "%d.%d.%d.%d" % (
        random.randint(0, 255), random.randint(0, 255),
        random.randint(0, 255), random.randint(0, 255)
    )
    port_src = random.randint(0, 65535)
    port_dst = random.randint(0, 65535)
    ip_src_array.append(ip_src)
    ip_dst_array.append(ip_dst)
    port_src_array.append(port_src)
    port_dst_array.append(port_dst)

syn_pkts = []
for idx in range(3):
    pkt = pcap_reader.read_packet()
    syn_pkts.append(pkt)
    pcap_writer.write(pkt)

for count in range(flow_count):
    for idx in range(3):
        new_pkt = Packet.copy(syn_pkts[idx])
        # print(syn_pkts[idx][IP].src)
        if new_pkt[IP].src == "10.0.0.2":
            new_pkt[IP].src = ip_src_array[count]
            new_pkt[IP].dst = ip_dst_array[count]
            new_pkt[TCP].src = port_src_array[count]
            new_pkt[TCP].dst = port_dst_array[count]
        else:
            new_pkt[IP].src = ip_dst_array[count]
            new_pkt[IP].dst = ip_src_array[count]
            new_pkt[TCP].src = port_dst_array[count]
            new_pkt[TCP].dst = port_src_array[count]
        pcap_writer.write(new_pkt)

print("SYN packets has been processed.")

# for idx in range(packet_count):
    # pkt = pcap_reader.read_packet()
    # pkt[Ether].src = "68:91:D0:61:B4:C5"
    # pkt[Ether].dst = "48:6E:73:00:04:DB"
    # pcap_writer.write(pkt)
    # if (idx + 1) % 10000 == 0:
        # print("%d packet has been processed\n" % (idx + 1))

http_pkts = []
for idx in range(8):
    pkt = pcap_reader.read_packet()
    http_pkts.append(pkt)
    pcap_writer.write(pkt)

for count in range(packet_count):
    num_rnd = random.randint(0, flow_count - 1)
    for idx in range(8):
        new_pkt = Packet.copy(http_pkts[idx])
        if new_pkt[IP].src == "10.0.0.2":
            new_pkt[IP].src = ip_src_array[num_rnd]
            new_pkt[IP].dst = ip_dst_array[num_rnd]
            new_pkt[TCP].src = port_src_array[num_rnd]
            new_pkt[TCP].dst = port_dst_array[num_rnd]
        else:
            new_pkt[IP].src = ip_dst_array[num_rnd]
            new_pkt[IP].dst = ip_src_array[num_rnd]
            new_pkt[TCP].src = port_dst_array[num_rnd]
            new_pkt[TCP].dst = port_src_array[num_rnd]
        new_pkt[TCP].payload = "i" * (packet_size - 54)
        pcap_writer.write(new_pkt)
    if (count + 1) % 10000 == 0:
        print("%d HTTP packets has been processed." % (count + 1))

print("HTTP packets has been processed.")

pcap_reader.read_packet()
pcap_reader.read_packet()

fin_pkts = []
for idx in range(3):
    pkt = pcap_reader.read_packet()
    fin_pkts.append(pkt)
    pcap_writer.write(pkt)

for count in range(flow_count):
    for idx in range(3):
        new_pkt = Packet.copy(fin_pkts[idx])
        if new_pkt[IP].src == "10.0.0.2":
            new_pkt[IP].src = ip_src_array[count]
            new_pkt[IP].dst = ip_dst_array[count]
            new_pkt[TCP].src = port_src_array[count]
            new_pkt[TCP].dst = port_dst_array[count]
        else:
            new_pkt[IP].src = ip_dst_array[count]
            new_pkt[IP].dst = ip_src_array[count]
            new_pkt[TCP].src = port_dst_array[count]
            new_pkt[TCP].dst = port_src_array[count]
        pcap_writer.write(new_pkt)

print("FIN packets has been processed.")

pcap_writer.flush()
pcap_writer.close()
