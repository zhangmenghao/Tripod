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


counts = 60
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


def extract3(ip):
    count = 0
    fn = "random_abnormal_"+ip+".txt"
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
def extract4(ip):
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
m208 = extract("208")[0:100]
m209 = extract("209")[0:100]
m210 = extract("210")[0:100]

b207 = extract2("207")
b208 = extract2("208")[0:100]
b209 = extract2("209")[0:100]
b210 = extract2("210")[0:100]


r207 = extract3("207")
r208 = extract3("208")[0:100]
r209 = extract3("209")[0:100]
r210 = extract3("210")[0:100]

s207 = extract4("207")
s208 = extract4("208")[0:100]
s209 = extract4("209")[0:100]
s210 = extract4("210")[0:100]

while len(m207) < len(m208):
    m207.append(0);
while len(b207) < len(b208):
    b207.append(0);
while len(r207) < len(r208):
    r207.append(0);
while len(s207) < len(s208):
    s207.append(0);


m = [m207[i] + m208[i] + m209[i] + m210[i] for i in range(0,65)]
b = [b207[i] + b208[i] + b209[i] + b210[i] for i in range(0,65)]
r = [r207[i] + r208[i] + r209[i] + r210[i] for i in range(0,65)]
s = [s207[i] + s208[i] + s209[i] + s210[i] + 3000 for i in range(0,65)]

timeline_detail = np.linspace(timeline.min(),timeline.max(),counts)
m_detail = spline(timeline,m[0:60],timeline_detail)
b_detail = spline(timeline,b[1:61],timeline_detail)
r_detail = spline(timeline,r[1:61],timeline_detail)
s_detail = spline(timeline,s[4:64],timeline_detail)


xmajorLocator   = MultipleLocator(1)
xmajorFormatter = FormatStrFormatter('%1.0f')
xminorLocator   = MultipleLocator(0.5)
  
ymajorLocator   = MultipleLocator(2500)
ymajorFormatter = FormatStrFormatter('%1.0f')
yminorLocator   = MultipleLocator(1250)

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
plt.ylim(0,27500) 
plt.xlim(0, 6)
plt.plot(timeline_detail, m_detail, '-', label="Tripod", linewidth=3)
plt.plot(timeline_detail, b_detail, '-', label="B", linewidth=3)
plt.plot(timeline_detail, r_detail, '-', label="R", linewidth=3)
plt.plot(timeline_detail, s_detail, '-', label="D", linewidth=3)

legend = plt.legend(loc='lower left', shadow=False, fontsize='large')

plt.xlabel('Time(s)', fontsize='large')
plt.ylabel('Throughput(Mbps)', fontsize='large')

plt.savefig('total_throughput.pdf')
plt.show()


