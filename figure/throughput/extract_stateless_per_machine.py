import sys
import os
import numpy as np
import matplotlib as mpl
import matplotlib.pyplot as plt
import brewer2mpl
from scipy.interpolate import spline
from matplotlib.ticker import MultipleLocator, FormatStrFormatter

bmap = brewer2mpl.get_map('Set1', 'qualitative', 5)
colors = bmap.mpl_colors
mpl.rcParams['axes.color_cycle'] = colors


counts = 74
timeline = np.array(range(0, counts, 1))
timeline = timeline / float(10)


def extract(ip):
    count = 0
    fn = "stateless_abnormal_"+ip+".txt"

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
m208 = extract("208")[0:counts]
m209 = extract("209")[0:counts]
m210 = extract("210")[0:counts]
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


xmajorLocator   = MultipleLocator(1)
xmajorFormatter = FormatStrFormatter('%1.0f')
xminorLocator   = MultipleLocator(0.5)
  
ymajorLocator   = MultipleLocator(1000)
ymajorFormatter = FormatStrFormatter('%1.0f')
yminorLocator   = MultipleLocator(500)

plt.figure(1)
ax = plt.subplot(111)

ax.xaxis.set_major_locator(xmajorLocator)  
ax.xaxis.set_major_formatter(xmajorFormatter)  
  
ax.yaxis.set_major_locator(ymajorLocator)  
ax.yaxis.set_major_formatter(ymajorFormatter)  
  
ax.xaxis.set_minor_locator(xminorLocator)  
ax.yaxis.set_minor_locator(yminorLocator)  
  
ax.xaxis.grid(True, which='major')
ax.yaxis.grid(True, which='major')
#plt.plot([0], [0])
#plt.plot([0], [0])

#plt.yscale('log')
plt.ylim(0,10000) 
plt.xlim(1, 7)
plt.plot(timeline_detail, m207_detail, '-', label="machine 1", linewidth=3)
plt.plot(timeline_detail, m208_detail, '-', label="machine 2", linewidth=3)
plt.plot(timeline_detail, m209_detail, '-', label="machine 3", linewidth=3)
plt.plot(timeline_detail, m210_detail, '-', label="machine 4", linewidth=3)

legend = plt.legend(loc='lower right', shadow=False, fontsize='large')

plt.xlabel('Time(s)', fontsize='large')
plt.ylabel('Throughput(Mbps)', fontsize='large')

plt.savefig('throughput_stateless_per_machine.pdf')
plt.show()


