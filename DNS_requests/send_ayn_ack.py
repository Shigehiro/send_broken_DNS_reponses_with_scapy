#!/usr/bin/env python3

"""
This script sends SYN,ACK packet
"""

import argparse
from scapy.all import *

parser = argparse.ArgumentParser()
parser.add_argument("-s", "--server-ip", required=True)
args = parser.parse_args()
server_ip = args.server_ip

ip = IP(dst=server_ip)
ack = 12345
tcp = TCP(sport=53, dport=32832, flags='SA', seq=0,ack=ack)
packet = ip / tcp
send(packet, count=1)
