#!/usr/bin/env python3

"""
Send DNS query by spoofing a source IP address
"""

import argparse
from scapy.all import *

parser = argparse.ArgumentParser()
parser.add_argument("-c", "--client-ip", required=False)
parser.add_argument("-s", "--server-ip", required=True)
args = parser.parse_args()

client_ip = args.client_ip
server_ip = args.server_ip

if not client_ip:
  query = "www.example.com"
  packet = (IP(dst=server_ip)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=query, qtype='A', qclass='IN')))
  send(packet, count=1)
else:
  query = "www.example.com"
  packet = (IP(src=client_ip, dst=server_ip)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=query, qtype='A', qclass='IN')))
  send(packet, count=1)
