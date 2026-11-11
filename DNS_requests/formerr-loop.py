#!/usr/bin/env python3

"""
Send malformed DNS queries
"""

import argparse
from scapy.all import *

parser = argparse.ArgumentParser()
parser.add_argument("-s", "--server-ip", required=True)
args = parser.parse_args()
server_ip = args.server_ip


def send_malformed_query(server_ip=server_ip):
    ip = IP(dst=server_ip)

    udp = UDP(sport=44444, dport=53)

    dns = DNS(
        id=12345,
        qd=DNSQR(qname='www.a.com', qtype='A', qclass='IN'),
        aa=0,
        rd=0,
        qr=0,
        rcode=0,
        qdcount=0,
        ancount=10000,
        nscount=10000,
        arcount=10000,
        an=DNSRR(
            rrname='www.google.com',
            type='A',
            ttl=3600,
            rdata='1.1.1.1')
        )

    # Build the packet
    packet = ip / udp / dns

    # Send the packet
    send(packet, count=100)

if __name__ == '__main__':
    send_malformed_query(server_ip=server_ip)
