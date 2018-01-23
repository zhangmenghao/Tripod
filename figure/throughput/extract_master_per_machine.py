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


counts = 100
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


m207 = extract("207")
m208 = extract("208")[0:100]
m209 = extract("209")[0:100]
m210 = extract("210")[0:100]
while len(m207) < len(m208):
    m207.append(0);

print m207
print m208
print m209
print m210

timeline_detail = np.linspace(timeline.min(),timeline.max(),counts)
m207_detail = spline(timeline,m207,timeline_detail)
m208_detail = spline(timeline,m208,timeline_detail)
m209_detail = spline(timeline,m209,timeline_detail)
m210_detail = spline(timeline,m210,timeline_detail)


plt.figure()
plt.plot([0], [0])
plt.plot([0], [0])
#plt.plot([0], [0])
#plt.plot([0], [0])

#plt.yscale('log')
plt.ylim(0,10000) 
plt.xlim(1, 7)
plt.plot(timeline_detail, m207_detail, '-', label="machine 1", linewidth=1)
plt.plot(timeline_detail, m208_detail, '-', label="machine 2", linewidth=1)
plt.plot(timeline_detail, m209_detail, '-', label="machine 3", linewidth=1)
plt.plot(timeline_detail, m210_detail, '-', label="machine 4", linewidth=1)
legend = plt.legend(loc='lower left', shadow=False, fontsize='medium')

plt.xlabel('Time(s)')
plt.ylabel('Throughput(MBps)')

plt.savefig('throughput_master_per_machine.pdf')
plt.show()


