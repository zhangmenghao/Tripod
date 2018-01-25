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
    fn = "./master_abnormal_large_"+ip+".txt"
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


plt.figure()
plt.plot([0], [0])
#plt.plot([0], [0])
#plt.plot([0], [0])

#plt.yscale('log')
plt.ylim(0,6000) 
plt.xlim(1, 7)
plt.plot(timeline_detail, m_detail, '-', label="TRIPOD", linewidth=1)
plt.plot(timeline_detail, r_detail, '-', label="Random", linewidth=1)

legend = plt.legend(loc='lower left', shadow=False, fontsize='medium')

plt.xlabel('Time(s)')
plt.ylabel('Throughput(MBps)')

plt.savefig('tmp.pdf')
plt.show()

