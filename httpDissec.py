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


def printGET(packet, file_name):
    httpLayer = packet['HTTP Request']
    print file_name, ': ', httpLayer.Method, ' ', httpLayer.Path, "\n"


def extract_next_file(packets, file_name):
    if len(packets) == 0:
        return False

    if not has_http_header(packets[0]):
        return False

    first = packets.pop(0)

    # if there is no Raw length file is zero
    if "Raw" not in first:
        return True

    f = open(file_name, 'wb')

    f.write(first['Raw'].load)
    while len(packets) > 0 and not has_http_header(packets[0]):
        pkt = packets.pop(0)
        f.write(pkt['Raw'].load)
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
    printGET(req, file_name)
    extract_next_file(answers, file_name)
    i += 1
    

