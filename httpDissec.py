# sudo apt-get install python-scapy
from scapy.all import *
# sudo pip install scapy_http
from scapy.layers import http
from scapy.layers.http import HTTPResponse
import sys
import os
import optparse


def has_http_header(packet):
    return packet.haslayer(HTTPResponse)

def transfering_chunked(packet):
    httpLayer = packet['HTTP Response']
    return ('Transfer-Encoding' in httpLayer.fields and 
		httpLayer.fields['Transfer-Encoding'] == 'chunked')


def printGET(packet, file_name):
    httpLayer = packet['HTTP Request']
    print file_name,': ', httpLayer.Method, ' ', httpLayer.Path, "\n"


def dechunk_file(filename):
	chunked = open(filename, 'r')
	dechunked = open('dechunked.tmp', 'w')
	while True:
		line = chunked.readline()

		if not line:
			break
		value16, _ = line.split('\r')
		value10 = int(value16, 16)

		dechunked.write(chunked.read(value10))
		# ignore '\r\n' the lies in the final of the chunk
		chunked.read(2)

	chunked.close()
	dechunked.close()
	# renaming the dechunked file to the original name
	os.remove(filename)
	os.rename('dechunked.tmp', filename)


def extract_next_file(packets, file_name):
    if len(packets) == 0:
        return False

    if not has_http_header(packets[0]):
        return False

    first = packets.pop(0)
    # if there is no Raw length file is zero
    if "Raw" not in first:
        return False

    f = open(file_name, 'wb')

    f.write(first['Raw'].load)
    while len(packets) > 0 and not has_http_header(packets[0]):
        pkt = packets.pop(0)
        f.write(pkt['Raw'].load)
    f.close()

    if transfering_chunked(first):
        dechunk_file(file_name)

    return True


def get_http_requests (packets):
    requests = []
    for pkt in packets:
        tcp = pkt['TCP']
        # destination port must be 80
        if tcp.dport == 80 and pkt.haslayer('HTTP'):
            requests.append(pkt)
    return requests


def get_http_responses (packets):
    answers = []
    for pkt in packets:
        tcp = pkt['TCP']
        # source port must be 80
        if tcp.sport == 80 and pkt.haslayer('HTTP'):
            answers.append(pkt)
    return answers

def extract_files_and_print_requests(packets, output_dir):
    requests = get_http_requests(packets)
    responses = get_http_responses(packets)

    i = 0
    for req in requests:
        file_name = output_dir + "/file_" + str(i)
        if extract_next_file(responses, file_name):
            printGET(req, file_name)
        i += 1


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

    output_dir = options.path_out
    # if output directory was passed with
    # a '/' at the end, like "out/"
    if output_dir[-1] == '/':
        output_dir = output_dir[0:(len(output_dir) - 1)] # remove this '/'

    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)

    packets = rdpcap(options.pcap_file)
    extract_files_and_print_requests(packets, output_dir)

    
if __name__ == "__main__":
    main()

