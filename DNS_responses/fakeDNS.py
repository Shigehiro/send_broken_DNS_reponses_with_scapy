from nserver import NameServer, Query, Response, A, AAAA, SOA, NS
import dnslib
from datetime import timedelta

server = NameServer("example")

base_domain = "example.com"

"""
@server.rule("{base_domain}", ["SOA"])
def soa_records(query: Query):
    return SOA("example.com.", "ns01.example.com.", 'admin.example.com.', 1234)

@server.rule("{base_domain}", ["NS"])
def ns_records(query: Query):
    return NS("example.com.", "ns01.example.com.", 300)

@server.rule("ns01.{base_domain}", ["A"])
def example_a_records(query: Query):
    return A(query.name, "192.168.110.150", 30)

@server.rule("*.{base_domain}", ["A"])
def example_a_records(query: Query):
    return A(query.name, "1.2.3.4", 30)

@server.rule("ns01.{base_domain}", ["AAAA"])
def res(query: Query):
    return AAAA(query.name, "::1", 30)

@server.rule("*.{base_domain}", ["AAAA"])
def res(query: Query):
    response = Response(error_code=dnslib.RCODE.REFUSED)
    return response
"""

@server.rule("tc.sub.{base_domain}", ["A", "AAAA"])
def res(query: Query):
    response = Response()
    response.header.tc = 1
    response.header.append(dnslib.DNSHeader.TC)
    #response.header.rcode = dnslib.RCODE.NOERROR
    #print(response)
    return response

@server.rule("fail.sub.{base_domain}", ["A", "AAAA"])
def res(query: Query):
    response = Response(error_code=dnslib.RCODE.SERVFAIL)
    return response

@server.rule("formerr.sub.{base_domain}", ["A", "AAAA"])
def res(query: Query):
    response = Response(error_code=dnslib.RCODE.FORMERR)
    return response

@server.rule("notimp.sub.{base_domain}", ["A", "AAAA"])
def res(query: Query):
    response = Response(error_code=dnslib.RCODE.NOTIMP)
    return response

@server.rule("refused.sub.{base_domain}", ["A", "AAAA"])
def res(query: Query):
    response = Response(error_code=dnslib.RCODE.REFUSED)
    return response

@server.rule("noerror.sub.{base_domain}", ["A", "AAAA"])
def res(query: Query):
    #response = Response(error_code=dnslib.RCODE.NOERROR)
    response = Response(error_code=dnslib.RCODE.NOERROR, authority=SOA('example.com', 'ns01.example.com', 'ns01.example.com', 1234))
    return response

@server.rule("**.sub.{base_domain}", ["A", "AAAA"])
def res(query: Query):
    response = Response()
    response = Response(error_code=dnslib.RCODE.NXDOMAIN, authority=SOA('example.com', 'ns01.example.com', 'ns01.example.com', 1234))
    return response

if __name__ == "__main__":
    server.run()
