#!/usr/bin/env python
# coding=utf-8

from scapy.utils import PcapReader, PcapWriter
from scapy.all import *

design_flow_count = 15

def hash_pkt(pkt):
    # ip string to int
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    sport = pkt[TCP].sport
    dport = pkt[TCP].dport
    return (hash(src_ip) + hash(dst_ip) + hash(sport) + hash(dport)) % design_flow_count

packet_count = 800000

pcap_reader = PcapReader("./flow1w.pcap")
pcap_writer = PcapWriter("./flow1w_aggregated.pcap")


# generate
src_ips = ["0.0.0.0"] * design_flow_count
dst_ips = ["0.0.0.0"] * design_flow_count
sports = [0] * design_flow_count
dports = [0] * design_flow_count

flow_syn = [False] * design_flow_count



# read & write
for count in range(packet_count):
    pkt = pcap_reader.read_packet()
    hash_val = hash_pkt(pkt)
    if flow_syn[hash_val] is False:
        src_ips[hash_val] = pkt[IP].src
        dst_ips[hash_val] = pkt[IP].dst
        sports[hash_val] = pkt[TCP].sport
        dports[hash_val] = pkt[TCP].dport
        flow_syn[hash_val] = True
        print("Bucket " + str(hash_val) + " has been set")
    else:
        pkt[IP].src = src_ips[hash_val]
        pkt[IP].dst = dst_ips[hash_val]
        pkt[TCP].sport = sports[hash_val]
        pkt[TCP].dport = dports[hash_val]
        pkt[TCP].flags = 0
    pcap_writer.write(pkt)
    if count % 10000 == 0:
        print("Processing " + str(count) + "...")

pcap_writer.flush()
pcap_writer.close()

