# sudo apt-get install python-scapy
from scapy.all import *
# sudo pip install scapy_http
from scapy.layers import http
import sys

packets = rdpcap("task07_f1.pcap")
requests = {}
answers = {}


for pkt in packets:
    tcp = pkt['TCP']
    # destination port must be 80
    if tcp.dport == 80:
        ip_id = pkt[IP].id
        requests[ip_id] = pkt

for pkt in packets:
    tcp = pkt['TCP']
    # source port must be 80
    if tcp.sport == 80:
        ip_id = pkt['IP'].id
        answers[ip_id] = pkt


print '=============== REQUESTS =================='
for ip_id in requests:
    req = requests[ip_id]
    req.show()
#    if req.haslayer(http):
#    if 'HTTP Request' in req:
#        httpreq = req.getlayer(http)
#        print '\o/\o/\o/\o/ HTTP REQUEST \o/\o/\o/\o/\o/\o/'
#        print httpreq
#    else:
#        print '/o\ /o\ /o\ NO HTTP REQUEST'


print '=============== ANSWERS =================='
for ip_id in answers:
    ans = answers[ip_id]
    ans.show()

