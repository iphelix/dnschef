

DNSMasterChef is a POC based on the original project DNSChef. I integrated my project [Dns-online-filter](https://github.com/NavyTitanium/Dns-online-filter) to it so it will only forward safe domains, while spoofing unsafe domains.

It will verify 'A' queries and forward directly all other type of requests. The script listen locally on port #5353, so you can forward BIND requests to it.

## Installation
The script work fine with Python3.6.
You will need the following python packages installed: **dnslib**, **pyasn**, **IPy** and **dnspython**.
```sh
pip3.6 install -r requirements.txt
```

## Running DNSMasterChef
```
    [root@localhost]# python3.6 dnsMasterChef.py
    [*] Listening on an alternative port 5353
    [*] DNSChef started on interface: 127.0.0.1 
    [*] Using the following nameservers: 208.67.222.222, 208.67.220.220
    [*] No parameters were specified. Running in full proxy mode
```
## Output when proxying safe domains
### Test 1
Client:
```
[root@localhost]# ping github.com
PING github.com (192.30.253.112) 56(84) bytes of data.
```
Script:
```
github.com is safe, proxying...
Filtering PTR requests not supported, Forwarding...
[02:27:25] 127.0.0.1: proxying the response of type 'PTR' for 112.253.30.192.in-addr.arpa
```
### Test 2
Client:
```
[root@localhost]# dig outlook.com
...
;; ANSWER SECTION:
outlook.com.            285     IN      A       40.97.116.82
outlook.com.            285     IN      A       40.97.128.194
outlook.com.            285     IN      A       40.97.148.226
outlook.com.            285     IN      A       40.97.153.146
...
```
Script:
```
outlook.com is safe, proxying...
```
## Output when receiving requests for unsafe domains
### Test 1
Client:
```
[root@localhost]# ping stat-dns.com
PING nortonconnectsafedrop.sinkhole (192.168.1.220) 56(84) bytes of data.
```
Script:
```
stat-dns.com Spoofing because it is filtered by NortonConnectSafe
```
### Test 2
Client:
```
[root@localhost]# dig thephonecompany.com
...
;; ANSWER SECTION:
thephonecompany.com.    5       IN      CNAME   quad9drop.sinkhole.
quad9drop.sinkhole.     8600    IN      A       192.168.1.220
...
```
Script:
```
thephonecompany.com Spoofing because it is filtered by Quad9
```


