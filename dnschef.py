#!/usr/bin/python3
# -*- coding: utf-8 -*-

from optparse import OptionParser, OptionGroup
from configparser import ConfigParser
from dnslib import *
from IPy import IP
import threading
import random
import operator
import time
import socketserver
import socket
import sys
import os
import binascii
import string
import base64
import time
import dns.resolver
import dns.query
import hashlib
import pyasn
import asyncio
import concurrent.futures
from datetime import datetime

# The database to correlate IP with ASN
asndb = pyasn.pyasn('ipasn_20171223.dat')

# Providers variable definition
Google = dns.resolver.Resolver()
Google.Name = "Google DNS"
Strongarm = dns.resolver.Resolver()
Strongarm.Name = "Strongarm"
Quad9 = dns.resolver.Resolver()
Quad9.Name = "Quad9"
SafeDNS = dns.resolver.Resolver()
SafeDNS.Name = "SafeDNS"
ComodoSecure = dns.resolver.Resolver()
ComodoSecure.Name = "ComodoSecure"
NortonConnectSafe = dns.resolver.Resolver()
NortonConnectSafe.Name = "NortonConnectSafe"

# Setting IP address of each DNS provider
Google.nameservers = ['8.8.8.8', '8.8.4.4']
Google.Sinkhole = '127.0.0.7'
Quad9.nameservers = ['9.9.9.9', '149.112.112.112']
Quad9.Sinkhole = '127.0.0.2'
Strongarm.nameservers = ['54.174.40.213', '52.3.100.184']
Strongarm.Sinkhole = '127.0.0.3'
SafeDNS.nameservers = ['195.46.39.39', '195.46.39.40']
SafeDNS.Sinkhole = '127.0.0.4'
ComodoSecure.nameservers = ['8.26.56.26', '8.20.247.20']
ComodoSecure.Sinkhole = '127.0.0.5'
NortonConnectSafe.nameservers = ['199.85.126.30', '199.85.127.30']
NortonConnectSafe.Sinkhole = '127.0.0.6'

# Query a provider and verify the answer
async def Query(domain,DnsResolver,asn_baseline,hash_baseline):
    try:
        # Get the A record for the specified domain with the specified provider
        Answers = DnsResolver.query(domain, "A")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):  # Domain did not resolve
        return [False, DnsResolver]

    Arecords = []  # List of anwsered IP
    for rdata in Answers:
        Arecords.append(rdata.address)

    # Compare the answer with the baseline to see if record(s) diff$
    if hashlib.md5(str(sorted(Arecords)).encode('utf-8')
                   ).hexdigest() != hash_baseline.hexdigest():
        if (asndb.lookup(sorted(Arecords)[0])[0] != asn_baseline):
            return [False, DnsResolver]

    return [True, DnsResolver]

# Creates the parallels tasks
async def main(domain,asn_baseline,hash_baseline):
    Providers = [Strongarm, NortonConnectSafe, ComodoSecure, Quad9, SafeDNS]
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        tasks = [
            asyncio.ensure_future(
                Query(domain, Providers[i], asn_baseline, hash_baseline))
            for i in range(len(Providers))
        ]

        for IsSafe, provider in await asyncio.gather( * tasks):
            if IsSafe == False:  # One DNS provider in the function 'check' returned False, so the domain is unsafe
                return [False, provider]
            pass
        # Function 'check' never returned False at this point, so the domain is
        # safe
        return [True, provider]

# Create the loop			
def loop(domain,asn_baseline,hash_baseline):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    result = loop.run_until_complete(main(domain, asn_baseline, hash_baseline))
    # A return is received, let's close the objects
    loop.run_until_complete(loop.shutdown_asyncgens())
    return result


#Establish a baseline with Google Public DNS and call function "loop"
def lauch(domain):
    hash_baseline = hashlib.md5()
    print('looking at : ' + domain)
    try:
        Answers_Google = Google.query(domain, "A")  # Lookup the 'A' record(s)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):  # Domain did not resolve
        return [False, Google]

    # Contain the returned A record(s)
    Arecords = []
    for rdata in Answers_Google:
        Arecords.append(rdata.address)

    # Fingerprint of the anwser is the sorted list of A record(s)
    hash_baseline.update(str(sorted(Arecords)).encode('utf-8'))
    # Looking the ASN of the first A record (sorted)
    asn_baseline = asndb.lookup(sorted(Arecords)[0])[0]
    return loop(domain, asn_baseline, hash_baseline)


# DNSHandler Mixin. The class contains generic functions to parse DNS requests and
# calculate an appropriate response based on user parameters.
class DNSHandler:

    def parse(self, data):
        response = ''
        try:
            # Parse data as DNS
            d = DNSRecord.parse(data)
        except Exception as e:

            print(('[%s] %s: ERROR: %s' % (time.strftime('%H:%M:%S'),
                                           self.client_address[0], 'invalid DNS request')))
            if self.server.log:
                self.server.log.write(
                    '[%s] %s: ERROR: %s\n' %
                    (time.strftime('%d/%b/%Y:%H:%M:%S %z'),
                     self.client_address[0],
                     'invalid DNS request'))
        else:

            # Only Process DNS Queries
            if QR[d.header.qr] == 'QUERY':
                qname = str(d.q.qname)

                # Chop off the last period
                if qname[-1] == '.': qname = qname[:-1]

                qtype = QTYPE[d.q.qtype]

                # Proxy the request
                if qtype not in ['SOA', 'A']:
                    print("Filtering " + qtype + " requests not supported, Forwarding...")
                    print (
                            "[%s] %s: proxying the response of type '%s' for %s" %
                            (time.strftime("%H:%M:%S"), self.client_address[0], qtype, qname))
                    if self.server.log:
                        self.server.log.write(
                            "[%s] %s: proxying the response of type '%s' for %s\n" %
                            (time.strftime("%d/%b/%Y:%H:%M:%S %z"), self.client_address[0], qtype, qname))

                    nameserver_tuple = random.choice(self.server.nameservers).split('#')
                    response = self.proxyrequest(data, *nameserver_tuple)
                else:
                    IsSafe, ProviderName = launch(qname)
                    if IsSafe:
                        print(qname + " is safe, proxying...")
                        nameserver_tuple = random.choice(self.server.nameservers).split('#')
                        response = self.proxyrequest(data, *nameserver_tuple)
                    else:
                        fake_records = dict()
                        fake_record = ProviderName.Sinkhole
                        fake_records[qtype] = qtype

                        # Create a custom response to the query
                        response = DNSRecord(DNSHeader(id=d.header.id, bitmap=d.header.bitmap, qr=1, aa=1, ra=1), q=d.q)

                        if qtype == "SOA":
                            mname, rname, t1, t2, t3, t4, t5 = fake_record.split(" ")
                            times = tuple([int(t) for t in [t1, t2, t3, t4, t5]])

                            # dnslib doesn't like trailing dots
                            if mname[-1] == ".":
                                mname = mname[:-1]
                            if rname[-1] == ".":
                                rname = rname[:-1]

                            response.add_answer(RR(qname, getattr(QTYPE, qtype),
                                                   rdata=RDMAP[qtype](mname, rname, times)))

                        elif qtype == "A":
                            if fake_record[-1] == ".":
                                fake_record = fake_record[:-1]
                            response.add_answer(RR(qname, getattr(QTYPE, qtype),rdata=RDMAP[qtype](fake_record)))

                        response = response.pack()
                        print(qname + ' Spoofing because it is filtered by ' + ProviderName.Name)
        return response

    # Find appropriate ip address to use for a queried name. The function can

    def findnametodns(self, qname, nametodns):
        # Make qname case insensitive

        qname = qname.lower()

        # Split and reverse qname into components for matching.

        qnamelist = qname.split('.')
        qnamelist.reverse()

        # HACK: It is important to search the nametodns dictionary before iterating it so that
        # global matching ['*.*.*.*.*.*.*.*.*.*'] will match last. Use sorting
        # for that.

        for (domain, host) in sorted(iter(list(nametodns.items())),
                                     key=operator.itemgetter(1)):

            # NOTE: It is assumed that domain name was already lowercased
            #       when it was loaded through --file, --fakedomains or --truedomains
            # don't want to waste time lowercasing domains on every request.

            # Split and reverse domain into components for matching

            domain = domain.split('.')
            domain.reverse()

            # Compare domains in reverse.

            for (a, b) in map(None, qnamelist, domain):
                if a != b and b != '*':
                    break
            else:

                # Could be a real IP or False if we are doing reverse matching
                # with 'truedomains'

                return host
        else:
            return False


# Obtain a response from a real DNS server.

    def proxyrequest(
            self,
            request,
            host,
            port='53',
            protocol='udp',
    ):
        reply = None
        try:
            if self.server.ipv6:

                if protocol == 'udp':
                    sock = socket.socket(socket.AF_INET6,
                                         socket.SOCK_DGRAM)
                elif protocol == 'tcp':
                    sock = socket.socket(socket.AF_INET6,
                                         socket.SOCK_STREAM)
            else:

                if protocol == 'udp':
                    sock = socket.socket(socket.AF_INET,
                                         socket.SOCK_DGRAM)
                elif protocol == 'tcp':
                    sock = socket.socket(socket.AF_INET,
                                         socket.SOCK_STREAM)

            sock.settimeout(3.0)

            # Send the proxy request to a randomly chosen DNS server

            if protocol == 'udp':
                sock.sendto(request, (host, int(port)))
                reply = sock.recv(1024)
                sock.close()
            elif protocol == 'tcp':

                sock.connect((host, int(port)))

                # Add length for the TCP request

                length = binascii.unhexlify('%04x' % len(request))
                sock.sendall(length + request)

                # Strip length from the response

                reply = sock.recv(1024)
                reply = reply[2:]

                sock.close()
        except Exception as e:

            print(('[!] Could not proxy request: %s' % e))
        else:
            return reply


# UDP DNS Handler for incoming requests

class UDPHandler(DNSHandler, socketserver.BaseRequestHandler):

    def handle(self):
        (data, socket) = self.request
        response = self.parse(data)

        if response:
            socket.sendto(response, self.client_address)


# TCP DNS Handler for incoming requests

class TCPHandler(DNSHandler, socketserver.BaseRequestHandler):

    def handle(self):
        data = self.request.recv(1024)

        # Remove the addition "length" parameter used in the
        # TCP DNS protocol

        data = data[2:]
        response = self.parse(data)

        if response:
            # Calculate and add the additional "length" parameter
            # used in TCP DNS protocol

            length = binascii.unhexlify('%04x' % len(response))
            self.request.sendall(length + response)


class ThreadedUDPServer(socketserver.ThreadingMixIn,
                        socketserver.UDPServer):

    # Override SocketServer.UDPServer to add extra parameters

    def __init__(
            self,
            server_address,
            RequestHandlerClass,
            nametodns,
            nameservers,
            ipv6,
            log,
    ):
        self.nametodns = nametodns
        self.nameservers = nameservers
        self.ipv6 = ipv6
        self.address_family = \
            (socket.AF_INET6 if self.ipv6 else socket.AF_INET)
        self.log = log

        socketserver.UDPServer.__init__(self, server_address,
                                        RequestHandlerClass)


class ThreadedTCPServer(socketserver.ThreadingMixIn,
                        socketserver.TCPServer):
    # Override default value

    allow_reuse_address = True

    # Override SocketServer.TCPServer to add extra parameters

    def __init__(
            self,
            server_address,
            RequestHandlerClass,
            nametodns,
            nameservers,
            ipv6,
            log,
    ):
        self.nametodns = nametodns
        self.nameservers = nameservers
        self.ipv6 = ipv6
        self.address_family = \
            (socket.AF_INET6 if self.ipv6 else socket.AF_INET)
        self.log = log

        socketserver.TCPServer.__init__(self, server_address,
                                        RequestHandlerClass)


# Initialize and start the DNS Server

def start_cooking(
        interface,
        nametodns,
        nameservers,
        tcp=False,
        ipv6=False,
        port='55',
        logfile=None,
):
    try:

        if logfile:
            log = open(logfile, 'a', 0)
            log.write('[%s] DNSChef is active.\n'
                      % time.strftime('%d/%b/%Y:%H:%M:%S %z'))
        else:
            log = None

        if tcp:
            print('[*] DNSChef is running in TCP mode')
            server = ThreadedTCPServer(
                (interface, int(port)),
                TCPHandler,
                nametodns,
                nameservers,
                ipv6,
                log,
            )
        else:
            server = ThreadedUDPServer(
                (interface, int(port)),
                UDPHandler,
                nametodns,
                nameservers,
                ipv6,
                log,
            )

        # Start a thread with the server -- that thread will then start
        # more threads for each request

        server_thread = threading.Thread(target=server.serve_forever)

        # Exit the server thread when the main thread terminates

        server_thread.daemon = True
        server_thread.start()

        # Loop in the main thread

        while True:
            time.sleep(100)
    except (KeyboardInterrupt, SystemExit):

        if log:
            log.write('[%s] DNSChef is shutting down.\n'
                      % time.strftime('%d/%b/%Y:%H:%M:%S %z'))
            log.close()

        server.shutdown()
        print('[*] DNSChef is shutting down.')
        sys.exit()
    except IOError:

        print('[!] Failed to open log file for writing.')
    except Exception as e:

        print(('[!] Failed to start the server: %s' % e))


if __name__ == '__main__':
    # Parse command line arguments
    parser = OptionParser(usage="dnschef.py [options]:\n")

    rungroup = OptionGroup(parser, "Optional runtime parameters.")
    rungroup.add_option("--logfile", action="store", help="Specify a log file to record all activity")
    rungroup.add_option("-i", "--interface", metavar="127.0.0.1 or ::1", default="127.0.0.1", action="store",
                        help='Define an interface to use for the DNS listener. By default, the tool uses 127.0.0.1 for IPv4 mode and ::1 for IPv6 mode.')
    rungroup.add_option("--nameservers", metavar="208.67.222.222#53 or 208.67.220.220#53",
                        default='208.67.222.222,208.67.220.220', action="store")
    rungroup.add_option("-t", "--tcp", action="store_true", default=False,
                        help="Use TCP DNS proxy instead of the default UDP.")
    rungroup.add_option("-p", "--port", action="store", metavar="5353", default="5353",
                        help='Port number to listen for DNS requests.')
    parser.add_option_group(rungroup)

    (options, args) = parser.parse_args()
    options.ipv6 = False

    # Main storage of domain filters
    # NOTE: RDMAP is a dictionary map of qtype strings to handling classes
    nametodns = dict()
    for qtype in list(RDMAP.keys()):
        nametodns[qtype] = dict()

    # Notify user about alternative listening port
    if options.port != '53':
        print(('[*] Listening on an alternative port %s' % options.port))


    print(('[*] DNSChef started on interface: %s ' % options.interface))

    # Use alternative DNS servers
    if options.nameservers:
        nameservers = options.nameservers.split(',')
        print(('[*] Using the following nameservers: %s'
               % ', '.join(nameservers)))

    print('[*] No parameters were specified. Running in full proxy mode')

    # Launch DNSChef
    start_cooking(
        interface=options.interface,
        nametodns=nametodns,
        nameservers=nameservers,
        tcp=options.tcp,
        ipv6=options.ipv6,
        port=options.port,
        logfile=options.logfile,
    )
