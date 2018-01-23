import sys
import os
import numpy as np
import matplotlib as mpl
import matplotlib.pyplot as plt
import brewer2mpl
from scipy.interpolate import spline

bmap = brewer2mpl.get_map('Set1', 'qualitative', 5)
colors = bmap.mpl_colors
mpl.rcParams['axes.color_cycle'] = colors


counts = 90
timeline = np.array(range(0, counts, 1))
timeline = timeline / float(10)


def extract(ip):
    count = 0
    fn = "master_abnormal_"+ip+".txt"
    res = []
    for line in open(fn,'r').readlines():
        lines = line.split(' ')
        if lines[0] == "nf_rx_throughput:" and int(lines[-2]) != 0:
            count += 1
            #print count,
            #print lines[-2],
            res.append(10*int(lines[-2]))
        if lines[0] == "flow_counts:" and lines[1] != '0,':
            #print lines[1]
            pass
    print
    return res

def extract2(ip):
    count = 0
    fn = "baseline_abnormal_"+ip+".txt"
    res = []
    for line in open(fn,'r').readlines():
        lines = line.split(' ')
        if lines[0] == "nf_rx_throughput:" and int(lines[-2]) != 0:
            count += 1
            #print count,
            #print lines[-2],
            res.append(10*int(lines[-2]))
        if lines[0] == "flow_counts:" and lines[1] != '0,':
            #print lines[1]
            pass
    print
    return res

m207 = extract("207")
m208 = extract("208")[0:100]
m209 = extract("209")[0:100]
m210 = extract("210")[0:100]

b207 = extract2("207")
b208 = extract2("208")[0:100]
b209 = extract2("209")[0:100]
b210 = extract2("210")[0:100]
while len(m207) < len(m208):
    m207.append(0);
while len(b207) < len(b208):
    b207.append(0);


m = [m207[i] + m208[i] + m209[i] + m210[i] for i in range(0,100)]
b = [b207[i] + b208[i] + b209[i] + b210[i] for i in range(0,100)]

timeline_detail = np.linspace(timeline.min(),timeline.max(),counts)
m_detail = spline(timeline,m[0:90],timeline_detail)
b_detail = spline(timeline,b[1:91],timeline_detail)


plt.figure()
plt.plot([0], [0])
#plt.plot([0], [0])
#plt.plot([0], [0])

#plt.yscale('log')
plt.ylim(0,40000) 
plt.xlim(1, 7)
plt.plot(timeline_detail, m_detail, '-', label="TRIPOD", linewidth=1)
plt.plot(timeline_detail, b_detail, '-', label="baseline", linewidth=1)

legend = plt.legend(loc='lower left', shadow=False, fontsize='medium')

plt.xlabel('Time(s)')
plt.ylabel('Throughput(MBps)')

plt.savefig('total_throughput.pdf')
plt.show()


