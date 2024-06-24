#!/usr/bin/env python3

"""
This script returns a DNS response with ECS.

Please send queries with +subnet /8 as below.
This scrip will return responses with /24

# dig @192.168.116.30 www.example.com +subnet=30.0.0.0/8

; <<>> DiG 9.11.36-RedHat-9.11.36-14.el8_10 <<>> @192.168.116.30 www.example.com +subnet=30.0.0.0/8
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 13153
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; CLIENT-SUBNET: 30.0.0.0/8/24
;; QUESTION SECTION:
;www.example.com.               IN      A

;; ANSWER SECTION:
www.example.com.        3600    IN      A       183.0.0.1
"""

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


    #if ecs_flag:
    #    print(address)

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
                ttl=86400,
                rdata='11.0.0.1')
            )

        response_packet = eth / ip / udp / dns
        sendp(response_packet, iface=net_interface)
    
    # if ECS exists in the request
    elif ecs_flag:

        return_address = str('.'.join(address.split('.')[0:-1]) + '.0').replace("'", '')

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
                ttl=3600,
                rdata=f'{random.randint(11,191)}.0.0.1'),
            ar=DNSRR(rrname='.', type='OPT', rclass=1232,
                    rdata=EDNS0ClientSubnet(optcode='edns-client-subnet', family=1, scope_plen=24, address=return_address))
            )

        response_packet = eth / ip / udp / dns
        sendp(response_packet, iface=net_interface)
        
# Sniff for a DNS query matching the 'packet_filter' and send a specially crafted reply
sniff(filter='ip and udp and dst port 53', store=0, prn=dns_reply)

