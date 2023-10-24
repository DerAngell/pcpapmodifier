#!/usr/bin/env python
from scapy.all import *
import argparse
import sys

# parsing script arguments ===========================================
parser = argparse.ArgumentParser(description="Small util that changes source and destination IPs and ports in pcap",
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("-s", "--src_ip", help="Source IP")
parser.add_argument("-d", "--dst_ip", help="Destination IP")
parser.add_argument("-S", "--src_port", help="Source port")
parser.add_argument("-D", "--dst_port", help="Destination port port")
parser.add_argument("-o", "--output", help="Modified pcap name", required=True)
parser.add_argument("orig_pcap", help="Original pcap")
args = parser.parse_args()
params = vars(args)
# ====================================================================

# Open pcap ==========================================================
try:
    orig_pcap = rdpcap(params["orig_pcap"])
except FileNotFoundError:
    print("Pcap file {0} is not found".format(params["orig_pcap"]))
    sys.exit(1)
# ====================================================================

# Setting original source and destination IPs and ports ==============
src_ip = orig_pcap[0]["IP"].src
dst_ip = orig_pcap[0]["IP"].dst

if orig_pcap[0].haslayer("TCP"):
    protocol = "TCP"
    src_port = orig_pcap[0]["TCP"].sport
    dst_port = orig_pcap[0]["TCP"].dport
else:
    protocol = "UDP"
    src_port = orig_pcap[0]["UDP"].sport
    dst_port = orig_pcap[0]["UDP"].dport


# ====================================================================


# functions =============================================================
def change_scr_ip(ip):
    for pac in orig_pcap:
        if pac["IP"].src == src_ip:
            pac["IP"].src = ip
        elif pac["IP"].dst == src_ip:
            pac["IP"].dst = ip


def change_dst_ip(ip):
    for pac in orig_pcap:
        if pac["IP"].src == dst_ip:
            pac["IP"].src = ip
        elif pac["IP"].dst == dst_ip:
            pac["IP"].dst = ip


def change_src_port(port):
    for pac in orig_pcap:
        if pac[protocol].sport == src_port:
            pac[protocol].sport = port
        elif pac[protocol].dport == src_port:
            pac[protocol].dport = port


def change_dst_port(port):
    for pac in orig_pcap:
        if pac[protocol].sport == dst_port:
            pac[protocol].sport = port
        elif pac[protocol].dport == dst_port:
            pac[protocol].dport = port


# =====================================

# changing IPs and ports if required ==
try:
    if params["src_ip"] is not None:
        change_scr_ip(params["src_ip"])
except socket.gaierror:
    print("Invalid source IP")
    sys.exit(1)

try:
    if params["dst_ip"] is not None:
        change_dst_ip(params["dst_ip"])
except socket.gaierror:
    print("Invalid destination IP")
    sys.exit(1)

try:
    if params["src_port"] is not None:
        change_src_port(int(params["src_port"]))
except ValueError:
    print("Source port should be in range 1-65535")
    sys.exit(1)

try:
    if params["dst_port"] is not None:
        change_dst_port(int(params["dst_port"]))
except ValueError:
    print("Destination port should be in range 1-65535")
    sys.exit(1)
# =====================================

try:
    wrpcap(params["output"], orig_pcap)
except ValueError:
    print("Port should be in range 1-65535")
    sys.exit(1)
