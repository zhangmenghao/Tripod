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
timeline = timeline / float(5)

def extract_packet(filename):
    normalflowdown = []
    normalflowup = []
    normalflow = []
    fi = open(filename, 'r')
    countt = 0
    for line in fi.readlines():
        lines = line.split(' ')
        #print lines
        if lines[0] == 'rx_pkts_sec:' and int(lines[-1].split(',')[0]) != 0:
            #print lines[1].split(',')[0]
            normalflowdown.append(int(lines[-1]))
            normalflowup.append(int(lines[1].split(',')[0]))
            normalflow.append(float(normalflowup[countt])/float(normalflowdown[countt]))
            countt = countt + 1
            if countt == counts:
                break
    print counts        
    fi.close()
    return normalflow


normalflow = extract_packet('normal.txt');
abnormalflow = extract_packet('master_abnormal.txt')
stateless_normalflow = extract_packet('stateless_normal.txt')
stateless_abnormalflow = extract_packet('stateless_abnormal.txt')

print timeline
print normalflow
print abnormalflow
print stateless_normalflow
print stateless_abnormalflow

print len(normalflow), len(abnormalflow), len(stateless_normalflow), len(stateless_abnormalflow)

timeline_detail = np.linspace(timeline.min(), timeline.max(), counts)
normalflow_detail = spline(timeline, normalflow, timeline_detail)
abnormalflow_detail = spline(timeline, abnormalflow, timeline_detail)
stateless_normalflow_detail = spline(timeline, stateless_normalflow, timeline_detail)
stateless_abnormalflow_detail = spline(timeline, stateless_abnormalflow, timeline_detail)

plt.figure()
plt.plot([0], [0])
plt.plot([0], [0])
plt.plot([0], [0])
plt.plot([0], [0])

#plt.yscale('log')
plt.ylim(0, 1.1)
plt.plot(timeline_detail, normalflow_detail, '-', label="Tripod", linewidth=1, marker='*')
plt.plot(timeline_detail, abnormalflow_detail, '-', label="Tripod-failure", linewidth=1, marker='s')
plt.plot(timeline_detail, stateless_normalflow_detail, '-', label="Stateless", linewidth=1, marker='^')
plt.plot(timeline_detail, stateless_abnormalflow_detail, '-', label="Stateless-failure", linewidth=1, marker='o')

legend = plt.legend(loc='lower left', shadow=False, fontsize='medium')

plt.xlabel('Time(s)')
plt.ylabel('Packet Drop Rate')

plt.savefig('packet_drop_rate.pdf')
plt.show()

