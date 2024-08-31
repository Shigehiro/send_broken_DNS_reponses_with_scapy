#!/usr/bin/env python3

"""
This script always forces TCP by returning the response with a truncate bit turned on.
You can add a delay before sending UDP responses, SYN, ACK, and TCP responses.

Reference
https://gist.githubusercontent.com/tintinweb/8523a9a43a2fb61a6770/raw/a62359896acb6e5071201c66b122d5b960d1c503/scapy_tcp_handshake.py

Ensure that ICMP destination unreachable and TCP RST packets are dropped using iptables, nftables, or firewalld.

```
table inet filter {
        chain input {
                type filter hook input priority 0; policy accept;
                icmp type destination-unreachable counter drop;
        } chain forward {
                type filter hook forward priority 0; policy accept;
        }
        chain output {
                type filter hook output priority 0; policy accept;
                icmp type destination-unreachable counter drop;
                tcp flags & (rst | ack) == rst | ack counter drop
                tcp flags & (rst) == rst counter drop
        }
}
```

"""

from scapy.all import *
import argparse
import time

parser = argparse.ArgumentParser()
parser.add_argument('-l', '--listen', type=str, required=True, help='Specify the IPv4 address to capture wire data.')
parser.add_argument('-i', '--interface', type=str, default='eth0', help='Specify the listening interface. default eth0')
parser.add_argument('-s', '--syn_ack_delay', type=float, default=0, help='Add delay before sending syn,ack')
parser.add_argument('-t','--tcp_delay', type=float, default=0, help='Add delay before sending the DNS answer over TCP')
parser.add_argument('-u', '--udp_delay', type=float, default=0, help='Add dleay before sending truncate response over UDP')

args = parser.parse_args()
listen = args.listen
net_interface = args.interface
syn_ack_delay = args.syn_ack_delay
tcp_delay = args.tcp_delay
udp_delay = args.udp_delay

def send_syn_ack(packet):
    eth = Ether(
        src=packet[Ether].dst,
        dst=packet[Ether].src
        )

    ip = IP(
        src=packet[IP].dst,
        dst=packet[IP].src
        )

    ack = packet[TCP].seq + 1

    tcp = TCP(
        dport=packet[TCP].sport,
        sport=packet[TCP].dport,
        flags='SA',
        seq=0,
        ack=ack
        )

    response_packet = eth / ip / tcp

    time.sleep(syn_ack_delay)
    sendp(response_packet, iface=net_interface)

def send_reset(packet):
    eth = Ether(
        src=packet[Ether].dst,
        dst=packet[Ether].src
        )

    ip = IP(
        src=packet[IP].dst,
        dst=packet[IP].src
        )

    seq = packet[TCP].ack
    ack = packet[TCP].seq

    tcp = TCP(
        dport=packet[TCP].sport,
        sport=packet[TCP].dport,
        flags='R',
        seq=seq,
        ack=ack
        )

    response_packet = eth / ip / tcp
    sendp(response_packet, iface=net_interface)

def send_answer(packet):
    eth = Ether(
        src=packet[Ether].dst,
        dst=packet[Ether].src
        )

    ip = IP(
        src=packet[IP].dst,
        dst=packet[IP].src
        )

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
            ttl=30,
            rdata='10.0.0.1')
        )

    seq = packet[TCP].ack
    ack = packet[TCP].seq

    tcp = TCP(
        dport=packet[TCP].sport,
        sport=packet[TCP].dport,
        flags='A',
        seq=seq,
        ack=ack
        )

    response_packet = eth / ip / tcp / dns
        
    time.sleep(tcp_delay)
    sendp(response_packet, iface=net_interface)

# Function that replies to DNS query
def dns_reply(packet):

    # Handle TCP packets
    if packet.haslayer(IP) and packet.haslayer(TCP):
        if packet[TCP].flags == 'S': # SYN
            print("RCV: SYN, Send SYN ACK")
            send_syn_ack(packet)
        elif packet[TCP].flags == 'A' and not packet.haslayer(DNS): # ACK 
            print("RCV: ACK")
        elif packet.haslayer(DNS): # DNS query over TCP
            print("DNS query over TCP")
            send_answer(packet)
        elif packet[TCP].flags == 'SA' and not packet.haslayer(DNS): # SYN+ACK
            print("RCV: SYN+ACK")
        elif packet[TCP].flags == 'R' and not packet.haslayer(DNS): # RST
            print("RCV: RST")
        elif packet[TCP].flags == 'F' and not packet.haslayer(DNS): # FIN
            print("RCV: FIN, Send RST")
            send_reset(packet)
        elif packet[TCP].flags == 'FA' and not packet.haslayer(DNS): # FIN+ACK
            print("RCV: FIN ACK, Send RST")
            send_reset(packet)
        else:
            print("Oops")

    # Handle UDP packets
    if packet.haslayer(IP) and packet.haslayer(UDP):

        eth = Ether(
            src=packet[Ether].dst,
            dst=packet[Ether].src
            )

        ip = IP(
            src=packet[IP].dst,
            dst=packet[IP].src
            )

        udp = UDP(
            dport=packet[UDP].sport,
            sport=packet[UDP].dport
            )

        # Return truncate
        dns = DNS(
            id=packet[DNS].id,
            qd=packet[DNS].qd,
            aa=1,
            tc=1,
            rd=0,
            qr=1,
            rcode=0,
            qdcount=1,
            ancount=0,
            nscount=0,
            arcount=0,
        )
            
        response_packet = eth / ip / udp / dns
            
        time.sleep(udp_delay)
        sendp(response_packet, iface=net_interface)

# Sniff for a DNS query
sniff(filter=f'dst host {listen} and dst port 53', iface=net_interface, store=0, prn=dns_reply)
