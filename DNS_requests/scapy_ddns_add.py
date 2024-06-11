#!/usr/bin/env python3
from scapy.all import *

"""
add a RR over DDNS
"""

r = sr1(IP(dst='192.168.212.100') / UDP(dport=53) / 
        DNS(opcode=5,
            qd=[DNSQR(qname='test01.com', qclass='IN', qtype='SOA')],
            ns=[DNSRR(rrname='bar.test01.com', rclass='IN', type='A', ttl=3000, rdata='127.0.0.1')]),
        verbose=0, timeout=5)
