          _                _          __
         | | version 0.4  | |        / _|
       __| |_ __  ___  ___| |__   ___| |_
      / _` | '_ \/ __|/ __| '_ \ / _ \  _|
     | (_| | | | \__ \ (__| | | |  __/ |
      \__,_|_| |_|___/\___|_| |_|\___|_|

           D O C U M E N T A T I O N

DNSChef is a highly configurable DNS proxy for Penetration Testers and Malware Analysts. A DNS proxy (aka "Fake DNS") is a tool used for application network traffic analysis among other uses. For example, a DNS proxy can be used to fake requests for "badguy.com" to point to a local machine for termination or interception instead of a real host somewhere on the Internet.

There are several DNS Proxies out there. Most will simply point all DNS queries a single IP address or implement only rudimentary filtering. DNSChef was developed as part of a penetration test where there was a need for a more configurable system. As a result, DNSChef is cross-platform application capable of forging responses based on inclusive and exclusive domain lists, supporting multiple DNS record types, matching domains with wildcards, proxying true responses for nonmatching domains, defining external configuration files, IPv6 and many other features. You can find detailed explanation of each of the features and suggested uses below.

The use of DNS Proxy is recommended in situations where it is not possible to force an application to use some other proxy server directly. For example, some mobile applications completely ignore OS HTTP Proxy settings. In these cases, the use of a DNS proxy server such as DNSChef will allow you to trick that application into forwarding connections to the desired destination.

Setting up a DNS Proxy
======================

Before you can start using DNSChef, you must configure your machine to use a DNS nameserver with the tool running on it. You have several options based on the operating system you are going to use:

* **Linux** - Edit */etc/resolv.conf* to include a line on the very top with your traffic analysis host (e.g add "nameserver 127.0.0.1"  if you are running locally). Alternatively, you can add a DNS server address using tools such as Network Manager. Inside the Network Manager open IPv4 Settings, select *Automatic (DHCP) addresses only* or *Manual* from the *Method* drop down box and edit *DNS Servers* text box to include an IP address with DNSChef running.

* **Windows** - Select *Network Connections* from the *Control Panel*. Next select one of the connections (e.g. "Local Area Connection"), right-click on it and select properties. From within a newly appearing dialog box, select *Internet Protocol (TCP/IP)* and click on properties. At last select *Use the following DNS server addresses* radio button and enter the IP address with DNSChef running. For example, if running locally enter 127.0.0.1.

* **OS X** - Open *System Preferences* and click on the *Network* icon. Select the active interface and fill in the *DNS Server* field. If you are using Airport then you will have to click on *Advanced...* button and edit DNS servers from there. Alternatively, you can edit */etc/resolv.conf* and add a fake nameserver to the very top there (e.g "nameserver 127.0.0.1").

* **iOS** - Open *Settings* and select *General*. Next select on *Wi-Fi* and click on a blue arrow to the right of an active Access Point from the list. Edit DNS entry to point to the host with DNSChef running. Make sure you have disabled Cellular interface (if available).

* **Android** - Open *Settings* and select *Wireless and network*.  Click on *Wi-Fi settings* and select *Advanced* after pressing the *Options* button on the phone. Enable *Use static IP* checkbox and configure a custom DNS server.

If you do not have the ability to modify device's DNS settings manually, then you still have several options involving techniques such as [ARP Spoofing](http://en.wikipedia.org/wiki/ARP_spoofing), [Rogue DHCP](http://www.yersinia.net/doc.htm) and other creative methods.

At last you need to configure a fake service where DNSChef will point all of the requests. For example, if you are trying to intercept web traffic, you must bring up either a separate web server running on port 80 or set up a web proxy (e.g. Burp) to intercept traffic. DNSChef will point queries to your proxy/server host with properly configured services.

Running DNSChef
===============

DNSChef is a cross-platform application developed in Python which should run on most platforms which have a Python interpreter. You can use the supplied *dnschef.exe* executable to run it on Windows hosts without installing a Python interpreter. This guide will concentrate on Unix environments; however, all of the examples below were tested to work on Windows as well.

Let's get a taste of DNSChef with its most basic monitoring functionality. Execute the following command as root (required to start a server on port 53):

    # ./dnschef.py

              _                _          __
             | | version 0.2  | |        / _|
           __| |_ __  ___  ___| |__   ___| |_
          / _` | '_ \/ __|/ __| '_ \ / _ \  _|
         | (_| | | | \__ \ (__| | | |  __/ |
          \__,_|_| |_|___/\___|_| |_|\___|_|
                       iphelix@thesprawl.org

    [*] DNSChef started on interface: 127.0.0.1
    [*] Using the following nameservers: 8.8.8.8
    [*] No parameters were specified. Running in full proxy mode


Without any parameters, DNSChef will run in full proxy mode. This means that all requests will simply be forwarded to an upstream DNS server (8.8.8.8 by default) and returned back to the quering host. For example, let's query an "A" record for a domain and observe results:

    $ host -t A thesprawl.org
    thesprawl.org has address 108.59.3.64

DNSChef will print the following log line showing time, source IP address, type of record requested and most importantly which name was queried:

    [23:54:03] 127.0.0.1: proxying the response of type 'A' for thesprawl.org

This mode is useful for simple application monitoring where you need to figure out which domains it uses for its communications.

DNSChef has full support for IPv6 which can be activated using *-6* or *--ipv6** flags. It works exactly as IPv4 mode with the exception that default listening interface is switched to ::1 and default DNS server is switched to 2001:4860:4860::8888. Here is a sample output:

    # ./dnschef.py -6
              _                _          __
             | | version 0.2  | |        / _|
           __| |_ __  ___  ___| |__   ___| |_
          / _` | '_ \/ __|/ __| '_ \ / _ \  _|
         | (_| | | | \__ \ (__| | | |  __/ |
          \__,_|_| |_|___/\___|_| |_|\___|_|
                       iphelix@thesprawl.org

    [*] Using IPv6 mode.
    [*] DNSChef started on interface: ::1
    [*] Using the following nameservers: 2001:4860:4860::8888
    [*] No parameters were specified. Running in full proxy mode
    [00:35:44] ::1: proxying the response of type 'A' for thesprawl.org
    [00:35:44] ::1: proxying the response of type 'AAAA' for thesprawl.org
    [00:35:44] ::1: proxying the response of type 'MX' for thesprawl.org

NOTE: By default, DNSChef creates a UDP listener. You can use TCP instead with the *--tcp* argument discussed later.

Intercept all responses
-----------------------

Now, that you know how to start DNSChef let's configure it to fake all replies to point to 127.0.0.1 using the *--fakeip* parameter:

    # ./dnschef.py --fakeip 127.0.0.1 -q
    [*] DNSChef started on interface: 127.0.0.1
    [*] Using the following nameservers: 8.8.8.8
    [*] Cooking all A replies to point to 127.0.0.1
    [23:55:57] 127.0.0.1: cooking the response of type 'A' for google.com to 127.0.0.1
    [23:55:57] 127.0.0.1: proxying the response of type 'AAAA' for google.com
    [23:55:57] 127.0.0.1: proxying the response of type 'MX' for google.com

In the above output you an see that DNSChef was configured to proxy all requests to 127.0.0.1. The first line of log at 08:11:23 shows that we have "cooked" the "A" record response to point to 127.0.0.1. However, further requests for 'AAAA' and 'MX' records are simply proxied from a real DNS server. Let's see the output from requesting program:

    $ host google.com localhost
    google.com has address 127.0.0.1
    google.com has IPv6 address 2001:4860:4001:803::1001
    google.com mail is handled by 10 aspmx.l.google.com.
    google.com mail is handled by 40 alt3.aspmx.l.google.com.
    google.com mail is handled by 30 alt2.aspmx.l.google.com.
    google.com mail is handled by 20 alt1.aspmx.l.google.com.
    google.com mail is handled by 50 alt4.aspmx.l.google.com.

As you can see the program was tricked to use 127.0.0.1 for the IPv4 address. However, the information obtained from IPv6 (AAAA) and mail (MX) records appears completely legitimate. The goal of DNSChef is to have the least impact on the correct operation of the program, so if an application relies on a specific mailserver it will correctly obtain one through this proxied request.

Let's fake one more request to illustrate how to target multiple records at the same time:

    # ./dnschef.py --fakeip 127.0.0.1 --fakeipv6 ::1 -q
    [*] DNSChef started on interface: 127.0.0.1
    [*] Using the following nameservers: 8.8.8.8
    [*] Cooking all A replies to point to 127.0.0.1
    [*] Cooking all AAAA replies to point to ::1
    [00:02:14] 127.0.0.1: cooking the response of type 'A' for google.com to 127.0.0.1
    [00:02:14] 127.0.0.1: cooking the response of type 'AAAA' for google.com to ::1
    [00:02:14] 127.0.0.1: proxying the response of type 'MX' for google.com

In addition to the --fakeip flag, I have now specified --fakeipv6 designed to fake 'AAAA' record queries. Here is an updated program output:

    $ host google.com localhost
    google.com has address 127.0.0.1
    google.com has IPv6 address ::1
    google.com mail is handled by 10 aspmx.l.google.com.
    google.com mail is handled by 40 alt3.aspmx.l.google.com.
    google.com mail is handled by 30 alt2.aspmx.l.google.com.
    google.com mail is handled by 20 alt1.aspmx.l.google.com.
    google.com mail is handled by 50 alt4.aspmx.l.google.com.

Once more all of the records not explicitly overriden by the application were proxied and returned from the real DNS server. However, IPv4 (A) and IPv6 (AAAA) were both faked to point to a local machine.

DNSChef supports multiple record types:

    +--------+--------------+-----------+--------------------------+
    | Record |  Description |Argument   | Example                  |
    +--------+--------------+-----------+--------------------------+
    |  A     | IPv4 address |--fakeip   | --fakeip 192.0.2.1       |
    |  AAAA  | IPv6 address |--fakeipv6 | --fakeipv6 2001:db8::1   |
    |  MX    | Mail server  |--fakemail | --fakemail mail.fake.com |
    |  CNAME | CNAME record |--fakealias| --fakealias www.fake.com |
    |  NS    | Name server  |--fakens   | --fakens ns.fake.com     |
    +--------+--------------+-----------+--------------------------+

NOTE: For usability not all DNS record types are exposed on the command line. Additional records such as PTR, TXT, SOA, etc. can be specified using the --file flag and an appropriate record header. See the [external definitions file](#external-definitions-file) section below for details.

At last let's observe how the application handles queries of type ANY:

    # ./dnschef.py --fakeip 127.0.0.1 --fakeipv6 ::1 --fakemail mail.fake.com --fakealias www.fake.com --fakens ns.fake.com -q
    [*] DNSChef started on interface: 127.0.0.1
    [*] Using the following nameservers: 8.8.8.8
    [*] Cooking all A replies to point to 127.0.0.1
    [*] Cooking all AAAA replies to point to ::1
    [*] Cooking all MX replies to point to mail.fake.com
    [*] Cooking all CNAME replies to point to www.fake.com
    [*] Cooking all NS replies to point to ns.fake.com
    [00:17:29] 127.0.0.1: cooking the response of type 'ANY' for google.com with all known fake records.

DNS ANY record queries results in DNSChef returning every faked record that it knows about for an applicable domain. Here is the output that the program will see:

    $ host -t ANY google.com localhost
    google.com has address 127.0.0.1
    google.com has IPv6 address ::1
    google.com mail is handled by 10 mail.fake.com.
    google.com is an alias for www.fake.com.
    google.com name server ns.fake.com.

Filtering domains
-----------------

Using the above example, consider you only want to intercept requests for *thesprawl.org* and leave queries to all other domains such as *webfaction.com* without modification. You can use the *--fakedomains* parameter as illustrated below:

    # ./dnschef.py --fakeip 127.0.0.1 --fakedomains thesprawl.org -q
    [*] DNSChef started on interface: 127.0.0.1
    [*] Using the following nameservers: 8.8.8.8
    [*] Cooking replies to point to 127.0.0.1 matching: thesprawl.org
    [00:23:37] 127.0.0.1: cooking the response of type 'A' for thesprawl.org to 127.0.0.1
    [00:23:52] 127.0.0.1: proxying the response of type 'A' for mx9.webfaction.com

From the above example the request for *thesprawl.org* was faked; however, the request for *mx9.webfaction.com* was left alone. Filtering domains is very useful when you attempt to isolate a single application without breaking the rest.

NOTE: DNSChef will not verify whether the domain exists or not before faking the response. If you have specified a domain it will always resolve to a fake value whether it really exists or not.

Reverse filtering
-----------------

In another situation you may need to fake responses for all requests except a defined list of domains. You can accomplish this task using the *--truedomains* parameter as follows:

    # ./dnschef.py --fakeip 127.0.0.1 --truedomains thesprawl.org,*.webfaction.com -q
    [*] DNSChef started on interface: 127.0.0.1
    [*] Using the following nameservers: 8.8.8.8
    [*] Cooking replies to point to 127.0.0.1 not matching: *.webfaction.com, thesprawl.org
    [00:27:57] 127.0.0.1: proxying the response of type 'A' for mx9.webfaction.com
    [00:28:05] 127.0.0.1: cooking the response of type 'A' for google.com to 127.0.0.1

There are several things going on in the above example. First notice the use of a wildcard (*). All domains matching *.webfaction.com will be reverse matched and resolved to their true values. The request for 'google.com' returned 127.0.0.1 because it was not on the list of excluded domains.

NOTE: Wildcards are position specific. A mask of type *.thesprawl.org will match www.thesprawl.org but not www.test.thesprawl.org. However, a mask of type *.*.thesprawl.org will match thesprawl.org, www.thesprawl.org and www.test.thesprawl.org.

External definitions file
-------------------------

There may be situations where defining a single fake DNS record for all matching domains may not be sufficient. You can use an external file with a collection of DOMAIN=RECORD pairs defining exactly where you want the request to go.

For example, let create the following definitions file and call it *dnschef.ini*:

    [A]
    *.google.com=192.0.2.1
    thesprawl.org=192.0.2.2
    *.wordpress.*=192.0.2.3

Notice the section header [A], it defines the record type to DNSChef. Now let's carefully observe the output of multiple queries:

    # ./dnschef.py --file dnschef.ini -q
    [*] DNSChef started on interface: 127.0.0.1
    [*] Using the following nameservers: 8.8.8.8
    [+] Cooking A replies for domain *.google.com with '192.0.2.1'
    [+] Cooking A replies for domain thesprawl.org with '192.0.2.2'
    [+] Cooking A replies for domain *.wordpress.* with '192.0.2.3'
    [00:43:54] 127.0.0.1: cooking the response of type 'A' for google.com to 192.0.2.1
    [00:44:05] 127.0.0.1: cooking the response of type 'A' for www.google.com to 192.0.2.1
    [00:44:19] 127.0.0.1: cooking the response of type 'A' for thesprawl.org to 192.0.2.2
    [00:44:29] 127.0.0.1: proxying the response of type 'A' for www.thesprawl.org
    [00:44:40] 127.0.0.1: cooking the response of type 'A' for www.wordpress.org to 192.0.2.3
    [00:44:51] 127.0.0.1: cooking the response of type 'A' for wordpress.com to 192.0.2.3
    [00:45:02] 127.0.0.1: proxying the response of type 'A' for slashdot.org

Both *google.com* and *www.google.com* matched the *\*.google.com* entry and correctly resolved to *192.0.2.1*. On the other hand *www.thesprawl.org* request was simply proxied instead of being modified. At last all variations of *wordpress.com*, *www.wordpress.org*, etc. matched the *\*.wordpress.\** mask and correctly resolved to *192.0.2.3*. At last an undefined *slashdot.org* query was simply proxied with a real response.

You can specify section headers for all other supported DNS record types including the ones not explicitly exposed on the command line: [A], [AAAA], [MX], [NS], [CNAME], [PTR], [NAPTR] and [SOA]. For example, let's define a new [PTR] section in the 'dnschef.ini' file:

    [PTR]
    *.2.0.192.in-addr.arpa=fake.com

Let's observe DNSChef's behavior with this new record type:

     ./dnschef.py --file dnschef.ini -q
    [sudo] password for iphelix:
    [*] DNSChef started on interface: 127.0.0.1
    [*] Using the following nameservers: 8.8.8.8
    [+] Cooking PTR replies for domain *.2.0.192.in-addr.arpa with 'fake.com'
    [00:11:34] 127.0.0.1: cooking the response of type 'PTR' for 1.2.0.192.in-addr.arpa to fake.com

And here is what a client might see when performing reverse DNS queries:

    $ host 192.0.2.1 localhost
    1.2.0.192.in-addr.arpa domain name pointer fake.com.

Some records require exact formatting. Good examples are SOA and NAPTR

    [SOA]
    *.thesprawl.org=ns.fake.com. hostmaster.fake.com. 1 10800 3600 604800 3600

    [NAPTR]
    *.thesprawl.org=100 10 U E2U+sip !^.*$!sip:customer-service@fake.com! .

See sample dnschef.ini file for additional examples.

Advanced Filtering
------------------

You can mix and match input from a file and command line. For example the following command uses both *--file* and *--fakedomains* parameters:

    # ./dnschef.py --file dnschef.ini --fakeip 6.6.6.6 --fakedomains=thesprawl.org,slashdot.org -q
    [*] DNSChef started on interface: 127.0.0.1
    [*] Using the following nameservers: 8.8.8.8
    [+] Cooking A replies for domain *.google.com with '192.0.2.1'
    [+] Cooking A replies for domain thesprawl.org with '192.0.2.2'
    [+] Cooking A replies for domain *.wordpress.* with '192.0.2.3'
    [*] Cooking A replies to point to 6.6.6.6 matching: *.wordpress.*, *.google.com, thesprawl.org
    [*] Cooking A replies to point to 6.6.6.6 matching: slashdot.org, *.wordpress.*, *.google.com, thesprawl.org
    [00:49:05] 127.0.0.1: cooking the response of type 'A' for google.com to 192.0.2.1
    [00:49:15] 127.0.0.1: cooking the response of type 'A' for slashdot.org to 6.6.6.6
    [00:49:31] 127.0.0.1: cooking the response of type 'A' for thesprawl.org to 6.6.6.6
    [00:50:08] 127.0.0.1: proxying the response of type 'A' for tor.com

Notice the definition for *thesprawl.org* in the command line parameter took precedence over *dnschef.ini*. This could be useful if you want to override values in the configuration file. slashdot.org still resolves to the fake IP address because it was specified in the *--fakedomains* parameter. tor.com request is simply proxied since it was not specified in either command line or the configuration file.

Other configurations
====================

For security reasons, DNSChef listens on a local 127.0.0.1 (or ::1 for IPv6) interface by default. You can make DNSChef listen on another interface using the *--interface* parameter:

    # ./dnschef.py --interface 0.0.0.0 -q
    [*] DNSChef started on interface: 0.0.0.0
    [*] Using the following nameservers: 8.8.8.8
    [*] No parameters were specified. Running in full proxy mode
    [00:50:53] 192.0.2.105: proxying the response of type 'A' for thesprawl.org

or for IPv6:

    # ./dnschef.py -6 --interface :: -q
    [*] Using IPv6 mode.
    [*] DNSChef started on interface: ::
    [*] Using the following nameservers: 2001:4860:4860::8888
    [*] No parameters were specified. Running in full proxy mode
    [00:57:46] 2001:db8::105: proxying the response of type 'A' for thesprawl.org

By default, DNSChef uses Google's public DNS server to make proxy requests. However, you can define a custom list of nameservers using the *--nameservers* parameter:

    # ./dnschef.py --nameservers 4.2.2.1,4.2.2.2 -q
    [*] DNSChef started on interface: 127.0.0.1
    [*] Using the following nameservers: 4.2.2.1, 4.2.2.2
    [*] No parameters were specified. Running in full proxy mode
    [00:55:08] 127.0.0.1: proxying the response of type 'A' for thesprawl.org

It is possible to specify non-standard nameserver port using IP#PORT notation:

    # ./dnschef.py --nameservers 192.0.2.2#5353 -q
    [*] DNSChef started on interface: 127.0.0.1
    [*] Using the following nameservers: 192.0.2.2#5353
    [*] No parameters were specified. Running in full proxy mode
    [02:03:12] 127.0.0.1: proxying the response of type 'A' for thesprawl.org

At the same time it is possible to start DNSChef itself on an alternative port using the *-p port#* parameter:

    # ./dnschef.py -p 5353 -q
    [*] Listening on an alternative port 5353
    [*] DNSChef started on interface: 127.0.0.1
    [*] Using the following nameservers: 8.8.8.8
    [*] No parameters were specified. Running in full proxy mode

DNS protocol can be used over UDP (default) or TCP. DNSChef implements a TCP mode which can be activated with the *--tcp* flag.

Internal architecture
=====================

Here is some information on the internals in case you need to adapt the tool for your needs. DNSChef is built on top of the SocketServer module and uses threading to help process multiple requests simultaneously. The tool is designed to listen on TCP or UDP ports (default is port 53) for incoming requests and forward those requests when necessary to a real DNS server over UDP.

The excellent [dnslib library](https://bitbucket.org/paulc/dnslib/wiki/Home) is used to dissect and reassemble DNS packets. It is particularly useful when generating response packets based on queries.

DNSChef is capable of modifing queries for records of type "A", "AAAA", "MX", "CNAME", "NS", "TXT", "PTR", "NAPTR", "SOA", "ANY". It is very easy to expand or modify behavior for any record. Simply add another **if qtype == "RECORD TYPE")** entry and tell it what to reply with.

Enjoy the tool and forward all requests and comments to iphelix [at] thesprawl.org.

Happy hacking!
 -Peter
