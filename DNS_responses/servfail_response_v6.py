#!/usr/bin/env python3
# Import scapy libraries
from scapy.all import *
import time

# Set the interface to listen and respond on
net_interface = "eth0"

# Function that replies to DNS query
def dns_reply(packet):

    # Construct the DNS packet
    # Construct the Ethernet header by looking at the sniffed packet
    eth = Ether(
        src=packet[Ether].dst,
        dst=packet[Ether].src
        )

    # Construct the IP header by looking at the sniffed packet
    ip = IPv6(
        src=packet[IPv6].dst,
        dst=packet[IPv6].src
        )

    # Construct the UDP header by looking at the sniffed packet
    udp = UDP(
        dport=packet[UDP].sport,
        sport=packet[UDP].dport
        )

    # Construct the DNS response by looking at the sniffed packet and manually

    dns = DNS(
        id=packet[DNS].id,
        qd=packet[DNS].qd,
        aa=1,
        rd=0,
        qr=1,
        rcode=2,
        qdcount=1,
        ancount=0,
        nscount=0,
        arcount=0,
        )
        
    # Put the full packet together
    response_packet = eth / ip / udp / dns

    # Send the DNS response
    sendp(response_packet, iface=net_interface, verbose=0)

# Sniff for a DNS query matching the 'packet_filter' and send a specially crafted reply
sniff(filter='ip6 and udp and dst port 53', store=0, prn=dns_reply)
