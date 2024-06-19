#!/usr/bin/env python3

"""
This script sends a DNS query with EDNS Client Subnet.
"""

from scapy.all import *
import random
 
query = "www.google.com"
src_ip = "20.0.0.1"
dst_ip = "192.168.101.10"
qtype = 'A'
ecs_address = '20.0.0.1'
ecs_optcode=8

# opt code 20730 is Experimental - CSUBNET - Client subnet (20730)
#ecs_optcode=20730

# Build a packet
packet = (
          IP(src=src_ip, dst=dst_ip)/
          UDP(dport=53)/
          DNS(id=random.randint(0,65535), rd=1,
              qd=DNSQR(qname=query, qtype=qtype, qclass='IN'),
              ar=DNSRROPT(rrname='.', type='OPT', rclass=4096,
              rdata=EDNS0ClientSubnet(optcode=ecs_optcode, source_plen=32, family=1, scope_plen=0, address=ecs_address))
          )
)
          
# Send the packet
sr(packet, verbose=True)
