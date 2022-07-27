#!/usr/bin/env python3
from scapy.all import *
 
for qtype in range(0,65536):
  query = "a.root-servers.net"
  packet = (IP(dst="172.20.0.10")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=query, qtype=qtype, qclass='IN')))
  res = sr(packet)
