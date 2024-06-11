#!/usr/bin/env python3
from scapy.all import *

"""
delete a RR over DDNS
"""

r = sr1(IP(dst='192.168.212.100') / UDP(dport=53) / 
        DNS(opcode=5,
            qd=[DNSQR(qname='test01.com', qclass='IN', qtype='SOA')],
            ns=[DNSRR(rrname='bar.test01.com', rclass='ANY', type=255, ttl=0, rdata="")]),
        verbose=0, timeout=5)
