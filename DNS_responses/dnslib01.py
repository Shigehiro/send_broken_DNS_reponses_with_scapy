import time
from dnslib import QTYPE, RCODE, RR, A, NS
from dnslib.server import DNSServer, BaseResolver

class CustomResolver(BaseResolver):
    def resolve(self, request, handler):
        # Create a blank reply record matching the transaction ID
        reply = request.reply()
        
        # Get the requested domain name and query type
        qname = request.q.qname
        qtype = request.q.qtype
        
        print(f"Received query: {qname} ({QTYPE[qtype]})")
        
        # intercept traffic for example.com (note the trailing dot for DNS nomenclature)
        if qname == "example.com." and qtype == QTYPE.A:
            # Append an A record response (IP address)
            #reply.add_answer(RR(qname, QTYPE.A, rdata=A("1.2.3.4"), ttl=60))
            reply.add_auth(RR(qname, QTYPE.NS, rdata=NS("ns1.foo."), ttl=60))
            reply.add_auth(RR(qname, QTYPE.NS, rdata=NS("ns2.bar."), ttl=60))
            reply.add_ar(RR("ns1.foo.", QTYPE.A, rdata=A("1.2.3.4"), ttl=60))
            reply.add_ar(RR("ns2.bar.", QTYPE.A, rdata=A("1.2.3.4"), ttl=60))
            reply.header.rcode = RCODE.NOERROR
            reply.header.aa = 0
            reply.header.ra = 0
            reply.header.ad = 0
        else:
            # Set return code to NXDOMAIN if the domain doesn't match
            reply.header.rcode = RCODE.NXDOMAIN
            
        return reply

if __name__ == '__main__':
    # Initialize your resolver logic
    resolver = CustomResolver()
    
    # Configure the DNSServer wrapper (defaults to port 53 via UDP)
    # Note: Use port > 1024 (like 8053) if you don't want to run Python as root/Administrator
    server = DNSServer(resolver, port=8053, address="127.0.0.1")
    
    print("Starting DNS server on 127.0.0.1:8053...")
    server.start_thread()  # Starts the server in a background thread
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping DNS server...")
    finally:
        server.stop()

