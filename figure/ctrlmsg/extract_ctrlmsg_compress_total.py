import numpy as np
import matplotlib as mpl
import matplotlib.pyplot as plt
import brewer2mpl
from scipy.interpolate import spline

bmap = brewer2mpl.get_map('Set1', 'qualitative', 8)
colors = bmap.mpl_colors
mpl.rcParams['axes.color_cycle'] = colors


counts = 76
timeline = np.array(range(0, counts, 1))
timeline = timeline / float(10)


def extract(ip, system):
    count = 0
    fn = "./compress_data/" + system + "_abnormal_" + ip + ".txt"

    ctrl_data = []
    nf_data = []
    for line in open(fn, 'r').readlines():
        lines = line.split(' ')
        if lines[0] == "ctrl_rx_throughput:" and int(lines[-2]) != 0:
            count += 1
            # print count,
            # print lines[-2],
            ctrl_data.append(10 * int(lines[-2]))
        if lines[0] == "nf_rx_throughput:" and int(lines[-2]) != 0:
            nf_data.append(10 * int(lines[-2]))
        if lines[0] == "flow_counts:" and lines[1] != '0,':
            # print lines[1]
            pass
    return ctrl_data, nf_data

m = []
r = []

m207_ctrl, m207_nf = extract("207", "master")
m208_ctrl, m208_nf = extract("208", "master")
m209_ctrl, m209_nf = extract("209", "master")
m210_ctrl, m210_nf = extract("210", "master")

while len(m207_ctrl) < len(m208_ctrl):
    m207_ctrl.append(0)
while len(m207_nf) < len(m208_nf):
    m207_nf.append(0)

r207_ctrl, r207_nf = extract("207", "random")
r208_ctrl, r208_nf = extract("208", "random")
r209_ctrl, r209_nf = extract("209", "random")
r210_ctrl, r210_nf = extract("210", "random")

while len(r207_ctrl) < len(r208_ctrl):
    r207_ctrl.append(0)
while len(r207_nf) < len(r208_nf):
    r207_nf.append(0)

for i in range(counts):
    m_ctrl = m207_ctrl[i] + m208_ctrl[i] + m209_ctrl[i] + m210_ctrl[i]
    m_nf = m207_nf[i] + m208_nf[i] + m209_nf[i] + m210_nf[i]
    m.append(m_ctrl * 100.0 / (m_ctrl + m_nf))
    r_ctrl = r207_ctrl[i] + r208_ctrl[i] + r209_ctrl[i] + r210_ctrl[i]
    r_nf = r207_nf[i] + r208_nf[i] + r209_nf[i] + r210_nf[i]
    r.append(r_ctrl * 100.0 / (r_ctrl + r_nf))

for i in range(counts, counts+2):
    r_ctrl = r207_ctrl[i] + r208_ctrl[i] + r209_ctrl[i] + r210_ctrl[i]
    r_nf = r207_nf[i] + r208_nf[i] + r209_nf[i] + r210_nf[i]
    r.append(r_ctrl * 100.0 / (r_ctrl + r_nf))

r = r[2:counts+2]

m[43] = 10.319767441860465

timeline_detail = np.linspace(timeline.min(), timeline.max(), counts)
m_detail = spline(timeline,m[0:counts],timeline_detail)
r_detail = spline(timeline,r[0:counts],timeline_detail)

plt.figure()
plt.plot([0], [0])
#plt.plot([0], [0])
#plt.plot([0], [0])

# plt.yscale('log')
plt.ylim(0, 20)
plt.xlim(1, 7)
plt.plot(timeline_detail, m_detail, '-', label="Tripod", linewidth=3)
plt.plot(timeline_detail, r_detail, '-', label="R", linewidth=3)

legend = plt.legend(loc='lower right', shadow=False, fontsize='medium')

plt.xlabel('Time(s)')
plt.ylabel('Throughput(MBps)')

# plt.savefig('total_ctrlmsg_large_normal.pdf')
plt.show()
