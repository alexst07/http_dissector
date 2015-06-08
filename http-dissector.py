#!/usr/bin/env python2

import pcap
import sys
import string
import time
import socket
import struct
import optparse

def main():
    p = optparse.OptionParser("usage: %prog -r <pcap-file> -d <output>")
    p.add_option('-r', help="Filename of the pcap file is required",
                 dest="pcap_file")
    p.add_option('-d', help="Output path of file is required",
                 dest="path_out")

    options, arguments = p.parse_args()

if __name__ == "__main__":
    main()

