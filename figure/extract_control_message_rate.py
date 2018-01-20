#!/usr/bin/env python

import os
import numpy as np
import matplotlib as mpl
import matplotlib.pyplot as plt
import brewer2mpl
from scipy.interpolate import spline

bmap = brewer2mpl.get_map('Set1', 'qualitative', 5)
colors = bmap.mpl_colors
mpl.rcParams['axes.color_cycle'] = colors


counts = 43

timeline = np.array(range(0, counts, 1))
timeline = timeline / float(5)   # 0.2 second interval

def extract_data_throughput(filename):
    normalflow = []
    fi = open(filename, 'r')
    countt = 0
    for line in fi.readlines():
        lines = line.split(' ')
        #print lines
        if lines[0] == 'rx_throughput:' and int(lines[-2].split(',')[0]) != 0:
            #print lines[1].split(',')[0]
            normalflow.append(int(lines[1]))
            countt = countt + 1
            if countt == counts:
                break
    print counts        
    fi.close()
    return normalflow

def extract_control_throughput(filename):
    normalflow = [0] * counts
    #print normalflow
    suffix = ['_207', '_208', '_209']
    for suff in suffix:
        temp = []
        fi = open(filename + suff + '.txt', 'r')
        countt = 0
        for line in fi.readlines():
            lines = line.split(' ')
            #print lines
            if lines[0] == 'ctrl_throughput:' and int(lines[1]) != 0:
                #print lines[1]
                temp.append(int(lines[1]))
                countt = countt + 1
                if countt == counts:
                    break
        print counts        
        fi.close()
        normalflow = [a+b for a, b in zip(normalflow,temp)]
        #print normalflow
    normal = [a/3 for a in normalflow]
    print normal
    return normal


datapacket = extract_data_throughput('normal.txt')
controlpacket = extract_control_throughput('normal')
stateless_datapacket = extract_data_throughput('stateless_normal.txt')
stateless_controlpacket = extract_control_throughput('stateless_normal')

print timeline
print datapacket
print controlpacket
print stateless_datapacket
print stateless_controlpacket

print len(datapacket), len(controlpacket)#, len(stateless_datapacket), len(stateless_controlpacket)


timeline_detail = np.linspace(timeline.min(), timeline.max(), counts)
normal_detail = spline(timeline, [float(a)/float(b) for a, b in zip(controlpacket,datapacket)], timeline_detail)
stateless_normal_detail = spline(timeline, 
    [float(a)/float(b) for a, b in zip(stateless_controlpacket,stateless_datapacket)], timeline_detail)


plt.figure()
plt.plot([0], [0])
plt.plot([0], [0])
#plt.plot([0], [0])
#plt.plot([0], [0])

#plt.yscale('log')
plt.ylim(0, 0.08)
plt.plot(timeline_detail, normal_detail, '-', label="Tripod", linewidth=1, marker='*')
#plt.plot(timeline_detail, abnormalflow_detail, '-', label="TRIPOD-abnormal", linewidth=1, marker='s')
plt.plot(timeline_detail, stateless_normal_detail, '-', label="Stateless", linewidth=1, marker='^')
#plt.plot(timeline_detail, stateless_abnormalflow_detail, '-', label="stateless-abnormal", linewidth=1, marker='o')

legend = plt.legend(loc='upper left', shadow=False, fontsize='medium')

plt.xlabel('Time(s)')
plt.ylabel('Control Packets/Data Packets')

plt.savefig('control_message_rate.pdf')
plt.show()

