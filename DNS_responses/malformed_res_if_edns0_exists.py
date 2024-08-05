#!/usr/bin/env python3

"""
This script will return a wrong response, such as a malformed packet, servfail, or format error if EDNS0 exists in the DNS request.
"""

from scapy.all import *

# Set the interface to listen and respond on
net_interface = "eth0"

# Function that replies to DNS query
def dns_reply(packet):

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

    # Here is an edns0 existence flag.
    try:
        # EDNS0 version is 0
        if packet[DNS].ar.version == 0:
            exist_edns = True
    except:
        exist_edns = False
        pass

    # If edns0 exists, return a malformed packet
    if exist_edns:
        print("Found EDNS0 in the request")

        # servfail
        servfail_dns = DNS(
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

        # formerr
        formerr_dns = DNS(
            id=packet[DNS].id,
            qd=packet[DNS].qd,
            aa=1,
            rd=0,
            qr=1,
            rcode=1,
            qdcount=1,
            ancount=0,
            nscount=0,
            arcount=0,
            )

        # normal response
        dns = DNS(
            id=packet[DNS].id,
            qd=packet[DNS].qd,
            aa=1,
            rd=0,
            qr=1,
            rcode=0,
            qdcount=1,
            ancount=1,
            nscount=0,
            arcount=0,
            an=DNSRR(
                rrname=packet[DNS].qd.qname,
                type='A',
                ttl=300,
                rdata='10.0.0.1')
            )

        # malformed packet
        payload = 'a' * 100

        response_packet = eth / ip / udp / payload
        #response_packet = eth / ip / udp / dns
        #response_packet = eth / ip / udp / servfail_dns
        #response_packet = eth / ip / udp / formerr_dns

        # Send the DNS response
        sendp(response_packet, iface=net_interface, verbose=0)

    # If edns0 does not exists, returns normal response
    elif not exist_edns:
        print("Did not find EDNS0 in the request")
        dns = DNS(
            id=packet[DNS].id,
            qd=packet[DNS].qd,
            aa=1,
            rd=0,
            qr=1,
            rcode=0,
            qdcount=1,
            ancount=1,
            nscount=0,
            arcount=0,
            an=DNSRR(
                rrname=packet[DNS].qd.qname,
                type='A',
                ttl=300,
                rdata='10.0.0.2')
            )
            
        response_packet = eth / ip / udp / dns

        # Send the DNS response
        sendp(response_packet, iface=net_interface, verbose=0)

# Sniff for a DNS query matching the 'packet_filter' and send a specially crafted reply
sniff(filter='ip and udp and dst port 53', iface=net_interface, store=0, prn=dns_reply)
