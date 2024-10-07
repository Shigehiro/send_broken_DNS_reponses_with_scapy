#!/usr/bin/env python3

"""
This script sends a DNS request which contains a DNS response.
"""

import argparse
from scapy.all import *

parser = argparse.ArgumentParser()
parser.add_argument("-s", "--server-ip", required=True)
args = parser.parse_args()
server_ip = args.server_ip

def send_malformed_query(server_ip=server_ip):
    ip = IP(dst=server_ip)

    udp = UDP(dport=53)

    dns = DNS(
        id=12345,
        qd=DNSQR(qname='www.google.com', qtype='A', qclass='IN'),
        aa=0,
        rd=1,
        qr=1,
        rcode=0,
        qdcount=1,
        ancount=0,
        nscount=0,
        arcount=0,
        an=DNSRR(
            rrname='www.google.com',
            type='A',
            ttl=3600,
            rdata='1.1.1.1')
        )

    # Build the packet
    packet = ip / udp / dns

    # Send the packet
    send(packet, count=1)

if __name__ == '__main__':
    send_malformed_query(server_ip=server_ip)
