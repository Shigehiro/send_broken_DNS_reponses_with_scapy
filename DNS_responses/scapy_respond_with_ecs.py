#!/usr/bin/env python3

from scapy.all import *

# Set the interface to listen and respond on
net_interface = "eth0"

# Function that replies to DNS query
def dns_reply(packet):

    source_plen = int()
    address = str()
    ecs_flag = 0

    # Check if ECS exists in the request
    if packet[DNS].ar.rdata:
        ardata = str(packet[DNS].ar.rdata)
        if 'EDNS0ClientSubnet' in ardata:
            ecs_flag = 1
            ecs_data = str(packet[DNS].ar.rdata).split()
            for item in ecs_data:
                if 'source_plen' in item:
                    source_plen = item.split('=')[-1]
                elif 'address' in item:
                    address = item.split('=')[-1]
        else:
            pass


    if ecs_flag:
        print(address)

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

    # if ECS does not exist in the request
    if not ecs_flag:
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
                rdata='11.0.0.1')
            )

        response_packet = eth / ip / udp / dns
        sendp(response_packet, iface=net_interface)
    
    # if ECS exists in the request
    elif ecs_flag:
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
            arcount=1,
            an=DNSRR(
                rrname=packet[DNS].qd.qname,
                type='A',
                ttl=300,
                rdata='12.0.0.1'),
            ar=DNSRR(rrname='.', type='OPT', rclass=1232,
                    rdata=EDNS0ClientSubnet(optcode='edns-client-subnet', family=1, scope_plen=24, address='20.0.0.0'))
            )

        response_packet = eth / ip / udp / dns
        sendp(response_packet, iface=net_interface)
        
# Sniff for a DNS query matching the 'packet_filter' and send a specially crafted reply
sniff(filter='ip and udp and dst port 53', store=0, prn=dns_reply)

