import sys
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.query
import dns.flags
import dns.name
import dns.dnssec
import dns.exception
import dns.rrset
import dns.rdataset
import dns.rdata
import dns.rdataclass
import dns.rdtypes
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

def get_additional_zone(r):
    for rrset in r.authority:
        str = rrset.to_text()
        zone = str[0:str.index(".")]
        return zone


#Get DNSKEY from relevant zone.
def acquireDNSKEYres(zone, nsaddr):
    requestDNSKEYmsg = dns.message.make_query(zone, dns.rdatatype.DNSKEY, want_dnssec=True)
    dnskeyResponse = dns.query.udp(requestDNSKEYmsg, nsaddr)
    return dnskeyResponse

def get_dnskeySet(dnskeyResponse):
    dnskeySet = dnskeyResponse.answer[0]
    return dnskeySet

#Get ksk rdataset from a dnskey set
def get_ksk(dnskeySet):
    keyList = []
    for key in dnskeySet:
        if key.flags == 257:
            keyList.append(key)
            zskset = dns.rdataset.from_rdata_list(100,keyList)
            return zskset
        else:
            continue

def get_ksk_tobevalidated(dnskeySet):
    for key in dnskeySet:
        if key.flags == 257:
            return key

#Get zsk rdataset from a dnskey set
def get_zsk(dnskeySet):
    keyList = []
    for key in dnskeySet:
        if key.flags == 256:
            keyList.append(key)
            zskset = dns.rdataset.from_rdata_list(100,keyList)
            return zskset
        else:
            continue

def get_dnskeyRRsig(dnskeyResponse):
    dnskeyRRsig = dnskeyResponse.answer[1]
    return dnskeyRRsig

def get_DSname(response):
    for rrset in response.authority:
        if rrset.rdtype is dns.rdatatype.from_text("DS"):
            DSname = rrset.name
            return DSname
        else:
            continue

def get_DS(response):
    for rrset in response.authority:
        if rrset.rdtype is dns.rdatatype.from_text("DS"):
            for DS in rrset:
                return DS
        else:
            continue

def get_DSset(response):
    for rrset in response.authority:
        if rrset.rdtype is dns.rdatatype.from_text("DS"):
            DSset = rrset
            return DSset
        else:
            continue

def get_DSRRsig(response):
    for rrset in response.authority:
        if rrset.rdtype is dns.rdatatype.from_text("RRSIG"):
            DSRRsig = rrset
            return DSRRsig
        else:
            continue

def get_A_RRsig(response):
    for rrset in response.answer:
        if rrset.rdtype is dns.rdatatype.from_text("RRSIG"):
            A_RRsig = rrset
            return A_RRsig
        else:
            continue

#Find the root public ksk
dnskeyResponse = acquireDNSKEYres('.', rootIP[0])
rootDNSKEYset = get_dnskeySet(dnskeyResponse)
rootKsk = get_ksk(rootDNSKEYset)

#Set program beginning time
timeBegin = time.time()


def get_answer(message, nsaddr, qtype, DS, zone):
    response = dns.query.udp(message, nsaddr)
    additional_ip_list = get_additional_ip_list(response)

    if response.answer:
        '''Print out the IP address and query info.'''
        A_RRsig = get_A_RRsig(response)
        dnskeyResponse = acquireDNSKEYres(zone, nsaddr)

        if dnskeyResponse.answer:
            dnskeySet = get_dnskeySet(dnskeyResponse)
            dnskeyRRsig = get_dnskeyRRsig(dnskeyResponse)
            childKsk = get_ksk_tobevalidated(dnskeySet)
            hashed_childKsk = dns.dnssec.make_ds(dns.name.from_text(zone), childKsk, 'SHA256')
            try:
                hashed_childKsk == DS
                print("DNSKEY KSK Validation Success")
            except dns.dns.dnssec.ValidationFailure:
                print ("DNSKEY KSK verification failed")
                return
        else:
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.from_text(qtype):
                    timeUse = time.time() - timeBegin
                    print(rrset.to_text())
                    print('\nQuery Time:', int(timeUse*1000), 'msec')
                    print('When:', time.asctime( time.localtime(time.time())))
                    print('\nMSG SIZE  rcvd:', len(rrset.to_text().encode('utf-8')))

    else:
        '''If not touch the end of the query pass, then Make validations and iterate zones'''
        #Condition 1 : At very beginning, verify the root zone
        if nsaddr == rootIP[0]:
            keys = {dns.name.from_text(".") : rootKsk}
            dnskeyResponse = acquireDNSKEYres('.', nsaddr)
            dnskeySet = get_dnskeySet(dnskeyResponse)
            dnskeyRRsig = get_dnskeyRRsig(dnskeyResponse)

            try:
                dns.dnssec.validate(dnskeySet, dnskeyRRsig, keys)
                print("DNSKEY Validation Success")
            except dns.dnssec.ValidationFailure:
                print ("DNSKEY verification failed")

            #Verify DS record
            DSname = get_DSname(response)
            DSset= get_DSset(response)
            DSRRsig = get_DSRRsig(response)
            zsk = get_zsk(dnskeySet)
            keys = {dns.name.from_text(".") : zsk}

            try:
                dns.dnssec.validate(DSset, DSRRsig, keys)
                print("DSpubksk Validation Success!")
            except dns.dnssec.ValidationFailure:
                print ("DSpubksk verification failed")
                return

            #update puksk to be self-zone's DS record
            DS = get_DS(response)
            zone = get_additional_zone(response)


        #Condition 2: not a root zone
        else:
            #(1)Varify the DNSKEY ksk first
            dnskeyResponse = acquireDNSKEYres(zone, nsaddr)
            dnskeySet = get_dnskeySet(dnskeyResponse)
            dnskeyRRsig = get_dnskeyRRsig(dnskeyResponse)

            childKsk = get_ksk_tobevalidated(dnskeySet)
            hashed_childKsk = dns.dnssec.make_ds(dns.name.from_text(zone), childKsk, 'SHA256')

            try:
                hashed_childKsk == DS
                print("DNSKEY KSK Validation Success")
            except dns.dns.dnssec.ValidationFailure:
                print ("DNSKEY KSK verification failed")
                return

            #(2)Verify DS record
            DSname = get_DSname(response)
            DSset = get_DSset(response)
            DSRRsig = get_DSRRsig(response)
            zsk = get_zsk(dnskeySet)
            keys = {dns.name.from_text(zone) : zsk}

            try:
                dns.dnssec.validate(DSset, DSRRsig, keys)
                print("DSpubksk Validation Success")
            except dns.dnssec.ValidationFailure:
                print ("DSpubksk verification failed")
                return

            #Get self-zone's DS record and next zone's zone name
            DS = get_DS(response)
            zone = get_additional_zone(response)

        #elif additional_ip_list:
        nsaddr = additional_ip_list[0]
        get_answer(message, nsaddr, qtype, DS, zone)

#Make different types of query
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

    q = dns.message.make_query(qname, qtype, want_dnssec=True)
    r = dns.query.udp(q, rootIP[0])
    print ("QUESTION SECTION:")
    print(r.question[0])

    print ("\nANSWER SECTION:")
    beginTime = time.time()
    pubksk = rootKsk
    zone = '.'
    get_answer(q, rootIP[0], qtype, pubksk, zone)
