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


counts = 90
timeline = np.array(range(0, counts, 1))
timeline = timeline / float(10)


def extract(ip):
    count = 0
    fn = "./master_abnormal_large/master_abnormal_large_"+ip+".txt"
    res = []
    for line in open(fn,'r').readlines():
        lines = line.split(' ')
        if lines[0] == "ctrl_rx_throughput:" and int(lines[-2]) != 0:
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
    fn = "./random_abnormal_large/random_abnormal_large_"+ip+".txt"
    res = []
    for line in open(fn,'r').readlines():
        lines = line.split(' ')
        if lines[0] == "ctrl_rx_throughput:" and int(lines[-2]) != 0:
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

r207 = extract2("207")
r208 = extract2("208")[0:counts]
r209 = extract2("209")[0:counts]
r210 = extract2("210")[0:counts]
while len(m207) < len(m208):
    m207.append(0);
while len(r207) < len(r208):
    r207.append(0);


m = [m207[i] + m208[i] + m209[i] + m210[i] for i in range(0,counts)]
r = [r207[i] + r208[i] + r209[i] + r210[i] for i in range(0,counts)]

timeline_detail = np.linspace(timeline.min(),timeline.max(),counts)
m_detail = spline(timeline,m[0:counts],timeline_detail)
r_detail = spline(timeline,r[0:counts],timeline_detail)


xmajorLocator   = MultipleLocator(1)
xmajorFormatter = FormatStrFormatter('%1.0f')
xminorLocator   = MultipleLocator(0.5)
  
ymajorLocator   = MultipleLocator(500)
ymajorFormatter = FormatStrFormatter('%1.0f')
yminorLocator   = MultipleLocator(250)

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

#plt.yscale('log')
plt.ylim(0,6000) 
plt.xlim(1, 7)
plt.plot(timeline_detail, m_detail, '-', label="Tripod", linewidth=3)
plt.plot(timeline_detail, r_detail, '-', label="R", linewidth=3)

legend = plt.legend(loc='lower left', shadow=False, fontsize='large')

plt.xlabel('Time(s)', fontsize='large')
plt.ylabel('Throughput(Mbps)', fontsize='large')

plt.savefig('total_ctrlmsg_large_abnormal.pdf')
plt.show()

