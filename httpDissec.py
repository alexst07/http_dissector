# sudo apt-get install python-scapy
from scapy.all import *
# sudo pip install scapy_http
from scapy.layers import http
from scapy.layers.http import HTTPResponse
import sys

packets = rdpcap("task07_f1.pcap")
requests = []
answers = []


def has_http_header(packet):
    return packet.haslayer(HTTPResponse)

for pkt in packets:
    tcp = pkt['TCP']
    # destination port must be 80
    if tcp.dport == 80 and pkt.haslayer('HTTP'):
        requests.append(pkt)

for pkt in packets:
    tcp = pkt['TCP']
    # source port must be 80
    if tcp.sport == 80 and pkt.haslayer('HTTP'):
        answers.append(pkt)


print '=============== REQUESTS =================='
i = 0
for req in requests:
    print 'Packet: ', i, "\n"
    i = i + 1
    req.show()



print '=============== ANSWERS =================='
i = 0
for ans in answers:
    print 'Packet: ', i, "\n"
    i = i + 1
    if has_http_header(ans):
    	print "HAS HEADER\n"
    else:
    	print "NO HEADER\n"
    ans.show()

