import sys

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
            res.append(int(lines[-2]))
        if lines[0] == "flow_counts:" and lines[1] != '0,':
            #print lines[1]
            pass
    print
    return res


m207 = extract("207")
m208 = extract("208")
m209 = extract("209")
m210 = extract("210")
del m210[0]

print len(m207)
print len(m208)
print len(m209)
print len(m210)
m = []
for i in range(0,30):
    if i < len(m207):
        a = m208[i] + m209[i] + m210[i] + m207[i] 
    else:
        a = m208[i] + m209[i] + m210[i]
    m.append(a)
print m
'''
m207 = open("master_abnormal_207.txt","r")
for line in m207.readlines():
    lines = line.split(' ')
    if lines[0] == "nf_rx_throughput:" and int(lines[-2]) != 0:
        print lines[-2],
    if lines[0] == "flow_counts:":
        print lines[1]

m208 = open("master_abnormal_208.txt","r")
for line in m208.readlines():
    lines = line.split(' ')
    if lines[0] == "nf_rx_throughput:" and int(lines[-2]) != 0:
        print lines[-2],
    if lines[0] == "flow_counts:":
        print lines[1]


m209 = open("master_abnormal_209.txt","r")
for line in m209.readlines():
    lines = line.split(' ')
    if lines[0] == "nf_rx_throughput:" and int(lines[-2]) != 0:
        print lines[-2],
    if lines[0] == "flow_counts:":
        print lines[1]

        

m210 = open("master_abnormal_210.txt","r")
for line in m210.readlines():
    lines = line.split(' ')
    if lines[0] == "nf_rx_throughput:" and int(lines[-2]) != 0:
        print lines[-2],
    if lines[0] == "flow_counts:":
        print lines[1]
'''
