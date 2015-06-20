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


def extract_next_file(packets, file_name):
    if ! has_http_header(packets[0]):
        return False

    first = packets.pop(0)
    f = open(file_name, 'w+')
    f.write(first['Raw'])
    while !has_http_header(packets[0]):
        pkt = packets.pop(0)
        f.write(pkt['Raw'])
    f.close()
    return True


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
    file_name = "file_" + str(i)
    printGET(file_name)
    extract_next_file(answer, file_name)
    i += 1
    

