import sys
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.query
import dns.name
import time


ROOT = [
    ("a.root-servers.net.", "198.41.0.4"),
    ("b.root-servers.net.", "192.228.79.201"),
    ("c.root-servers.net.", "192.33.4.12"),
    ("d.root-servers.net.", "199.7.91.13"),
    ("e.root-servers.net.", "192.203.230.10"),
    ("f.root-servers.net.", "192.5.5.241"),
    ("g.root-servers.net.", "192.112.36.4"),
    ("h.root-servers.net.", "198.97.190.53"),
    ("i.root-servers.net.", "192.36.148.17"),
    ("j.root-servers.net.", "192.58.128.30"),
    ("k.root-servers.net.", "193.0.14.129"),
    ("l.root-servers.net.", "199.7.83.42"),
    ("m.root-servers.net.", "202.12.27.33"),]

rootIP = []
for name, addr in ROOT:
    name = dns.name.from_text(name)
    rootIP.append(addr)

def get_additional_ip_list(r):
    iplist = []
    for rrset in r.additional:
        if rrset.rdtype in [dns.rdatatype.A]:
            for rr in rrset:
                iplist.append(rr.to_text())
    return iplist

timeBegin = time.time()
def get_answer(message, nsaddr, qtype):
    response = dns.query.udp(message, nsaddr)
    additional_ip_list = get_additional_ip_list(response)

    if response.answer:
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.from_text(qtype):
                timeUse = time.time() - timeBegin
                print(rrset.to_text())
                print('\nQuery Time:', int(timeUse*1000), 'msec')
                print('When:', time.asctime( time.localtime(time.time())))
                print('\nMSG SIZE  rcvd:', len(rrset.to_text().encode('utf-8')))
            elif rrset.rdtype == 2:
                message = dns.message.make_query(rrset[0].to_text(), qtype, want_dnssec=False)
                nsaddr = rootIP[0]
                get_answer(message, nsaddr, qtype)
            else:
                message = dns.message.make_query(rrset[0].to_text(), qtype, want_dnssec=False)
                nsaddr = rootIP[0]
                get_answer(message, nsaddr, qtype)

    elif not response.additional:
        if qtype == "A":
            '''handle google.co.jp situations'''
            for rrset in response.authority:
                message = dns.message.make_query(rrset[0].to_text(), qtype, want_dnssec=False)
                nsaddr = rootIP[0]
                get_answer(message, nsaddr, qtype)
        else:
            '''for NS query'''
            for rrset in response.authority:
                timeUse = time.time() - timeBegin
                print(rrset.to_text())
                print('\nQuery Time:', int(timeUse*1000), 'msec')
                print('When:', time.asctime( time.localtime(time.time())))
                print('\nMSG SIZE  rcvd:', len(rrset.to_text().encode('utf-8')))

    elif additional_ip_list:
        '''update query address'''
        nsaddr = additional_ip_list[0]
        get_answer(message, nsaddr, qtype)


#make different types of query
def make_query(qname, qtype, want_dnssec=False):
    type = 0;
    if qtype is "A":
        type = 1
        message = dns.message.make_query(qname, type, want_dnssec=False)
        return message
    elif qtype is "NS":
        type = 2
        message = dns.message.make_query(qname, type, want_dnssec=False)
        return message
    elif qtype is "MX":
        type = 15
        message = dns.message.make_query(qname, type, want_dnssec=False)
        return message


if __name__ == '__main__':
    qname = sys.argv[1]
    qtype = sys.argv[2]

    q = dns.message.make_query(qname, qtype, want_dnssec=False)
    r = dns.query.udp(q, rootIP[0])
    print ("QUESTION SECTION:")
    print(r.question[0])

    print ("\nANSWER SECTION:")
    beginTime = time.time()
    get_answer(q, rootIP[0], qtype)
