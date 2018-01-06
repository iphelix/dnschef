

DNSMasterChef is a POC based on the original project DNSChef. I integrated my project [Dns-online-filter](https://github.com/NavyTitanium/Dns-online-filter) to it so it will only forward safe domains, while spoofing unsafe domains.

It will verify 'A' queries and forward directly all other type of requests. The script listen locally on port #5353, so you can forward BIND requests to it.

## Running DNSMasterChef
```
    [root@localhost]# python3.6 dnsMasterChef.py
    [*] Listening on an alternative port 5353
    [*] DNSChef started on interface: 127.0.0.1 
    [*] Using the following nameservers: 208.67.222.222, 208.67.220.220
    [*] No parameters were specified. Running in full proxy mode
```
## Output when proxying safe domains
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
## Output when receiving a request for an unsafe domain
Client:
```
[root@localhost]# ping stat-dns.com
PING nortonconnectsafedrop.local (192.168.1.220) 56(84) bytes of data.
```
Script:
```
stat-dns.com Spoofing because it is filtered by NortonConnectSafe
```
Client:
```
[root@localhost]# dig rixrax.com
...
;; ANSWER SECTION:
rixrax.com.             5       IN      CNAME   drop.local.
drop.local.             8600    IN      A       192.168.1.220
...
```
Script:
```
rixrax.com Spoofing because it is filtered by Strongarm
```


