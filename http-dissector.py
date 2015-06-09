#!/usr/bin/env python2

import pcapy
import sys
import string
import time
import socket
import struct
import optparse

def parse_packet(packet):
    print packet

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

