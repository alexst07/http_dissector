# sudo apt-get install python-scapy
from scapy.all import *
# sudo pip install scapy_http
from scapy.layers import http
from scapy.layers.http import HTTPResponse
import sys

packets = rdpcap("task07_f1.pcap")
requests = {}
answers = {}


def has_http_header(packet):
    return ans.haslayer(HTTPResponse)

for pkt in packets:
    tcp = pkt['TCP']
    # destination port must be 80
    if tcp.dport == 80 and pkt.haslayer('HTTP'):
        ip_id = pkt[IP].id
        requests[ip_id] = pkt

for pkt in packets:
    tcp = pkt['TCP']
    # source port must be 80
    if tcp.sport == 80 and pkt.haslayer('HTTP'):
        ip_id = pkt['IP'].id
        answers[ip_id] = pkt


print '=============== REQUESTS =================='
i = 0
for ip_id in requests:
    print 'Packet: ', i, "\n"
    i = i + 1
    req = requests[ip_id]
    req.show()
'''    if req.haslayer('HTTP'):
#    if 'HTTP Request' in req:
        httpreq = req.getlayer('HTTP')
        print '\o/\o/\o/\o/ HTTP REQUEST \o/\o/\o/\o/\o/\o/'
        print httpreq
    else:
        print '/o\ /o\ /o\ NO HTTP REQUEST'
    	'''


print '=============== ANSWERS =================='
i = 0
for ip_id in answers:
    print 'Packet: ', i, "\n"
    i = i + 1
    ans = answers[ip_id]
    if has_http_header(ans):
    	print "HAS HEADER\n"
    else:
    	print "NO HEADER\n"
    ans.show()

