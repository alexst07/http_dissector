#!/usr/bin/env python2

import pcapy
import sys
import string
import time
import socket
import struct
import optparse

def parser_ip_packet(s):
    d={}
    d['version']=(ord(s[0]) & 0xf0) >> 4
    d['header_len']=ord(s[0]) & 0x0f
    d['tos']=ord(s[1])
    d['total_len']=socket.ntohs(struct.unpack('H',s[2:4])[0])
    d['id']=socket.ntohs(struct.unpack('H',s[4:6])[0])
    d['flags']=(ord(s[6]) & 0xe0) >> 5
    d['fragment_offset']=socket.ntohs(struct.unpack('H',s[6:8])[0] & 0x1f)
    d['ttl']=ord(s[8])
    d['protocol']=ord(s[9])
    d['checksum']=socket.ntohs(struct.unpack('H',s[10:12])[0])
    d['source_address']=socket.inet_ntoa(s[12:16])
    d['destination_address']=socket.inet_ntoa(s[16:20])
    if d['header_len']>5:
        d['options']=s[20:4*(d['header_len']-5)]
    else:
        d['options']=None
        d['data']=s[4*d['header_len']:]
    return d

def parse_packet(packet):
    #parse ethernet header
    if packet[12:14] == '\x08\x00':
        p = parser_ip_packet(packet)
        print p


def main():
    p = optparse.OptionParser("usage: %prog -r <pcap-file> -d <output>")
    p.add_option('-r', help="Filename of the pcap file is required",
                 dest="pcap_file")
    p.add_option('-d', help="Output path of file is required",
                 dest="path_out")

    options, arguments = p.parse_args()

    if not options.pcap_file or not options.path_out:
        p.print_usage()
        return

    cap = pcapy.open_offline(options.pcap_file)

    while(1):
        (header, packet) = cap.next()
        parse_packet(packet)


if __name__ == "__main__":
    main()

