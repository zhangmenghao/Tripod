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


counts = 95

timeline = np.array(range(0, counts, 1))
#timeline = timeline / float(5)

def extract_latency(filename):
    normalflow = []
    fi = open(filename, 'r')
    countt = 0
    tt = 0
    sums = 0
    for line in fi.readlines():
        lines = line.split(' ')
        if int(lines[0]) == 0:
            pass
        elif int(lines[0]) % 10000 == 0:
            countt = countt + 1 
            #print sums, tt
            normalflow.append(sums/tt)
            sums = 0
            tt = 0
        else:
            if int(lines[1]) > 50000:
                pass
            else:
                sums = sums + int(lines[1])
                tt = tt + 1
        if countt == counts:
            break
    print countt       
    fi.close()
    normalflow = [a/2.4/1000 for a in normalflow]
    #print normalflow
    return normalflow


normalflow = extract_latency('master_latency.txt') 
#abnormalflow = extract_latency('master_abnormal.txt')
stateless_normalflow = extract_latency('stateless_latency.txt')
#stateless_abnormalflow = extract_latency('stateless_abnormal.txt')

print timeline
print normalflow
#print abnormalflow
print stateless_normalflow
#print stateless_abnormalflow

#print len(normalflow), len(stateless_normalflow)

timeline_detail = np.linspace(timeline.min(), timeline.max(), counts)
normalflow_detail = spline(timeline, normalflow, timeline_detail)
#abnormalflow_detail = spline(timeline, abnormalflow, timeline_detail)
stateless_normalflow_detail = spline(timeline, stateless_normalflow, timeline_detail)
#stateless_abnormalflow_detail = spline(timeline, stateless_abnormalflow, timeline_detail)

plt.figure()
plt.plot([0], [0])
plt.plot([0], [0])
#plt.plot([0], [0])
#plt.plot([0], [0])

#plt.yscale('log')
plt.ylim(0, 18)
plt.plot(timeline_detail, normalflow_detail, '-', label="Tripod", linewidth=1)
#plt.plot(timeline_detail, abnormalflow_detail, '-', label="TRIPOD-abnormal", linewidth=1, marker='s')
plt.plot(timeline_detail, stateless_normalflow_detail, '-', label="Stateless", linewidth=1)
#plt.plot(timeline_detail, stateless_abnormalflow_detail, '-', label="stateless-abnormal", linewidth=1, marker='o')

legend = plt.legend(loc='lower left', shadow=False, fontsize='medium')

plt.xlabel('Time(s)')
plt.ylabel('Latency(us)')

plt.savefig('packet_latency.pdf')

