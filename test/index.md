Query 
* Quad9 (9.9.9.9, 149.112.112.112)
* Strongarm (54.174.40.213, 52.3.100.184)
* SafeDNS (195.46.39.39, 195.46.39.40)
* ComodoSecure (8.26.56.26, 8.20.247.20)
* NortonConnectSafe (199.85.126.30, 199.85.127.30)

public DNS resolvers in parallels to verify if the domain is safe.
If a provider returns either NXdomain, Nodata or a sinkholed IP address for a specified domain, it  will end other queries and return False (domain unsafe).
If all providers correctly resolve the domain, it will be considered safe.

You can add as many threat blocking DNS providers as you want to the script, those 5 providers were choose only for the POC.

## Setup
Requires Python 3.6.
### Python packages
* [dnspython](https://pypi.python.org/pypi/dnspython)
* [asyncio](https://docs.python.org/3/library/asyncio.html)
* [pyasn](https://github.com/hadiasghari/pyasn)

## IP to ASN database
You also need to provide a IP to ASN database for pyasn. 

I strongly suggest that you update the database with [the following script](https://github.com/hadiasghari/pyasn/blob/master/pyasn-utils/pyasn_util_download.py)

## Usage

async-test.py domains.txt
## Output
```
[root@localhost tmp]# python3.6 async-test.py domains.txt 
google.com --> safe
cnn.com --> safe
stat-dns.com --> unsafe, filtered by NortonConnectSafe
www.zonemach.com --> unsafe, filtered by Strongarm
www.yasli-sad.ru --> unsafe, filtered by Strongarm
www.vinhosportimao.com --> unsafe, filtered by Strongarm
www.unblocking-acccount.000webhostapp.com --> unsafe, filtered by Strongarm
www.thephonecompany.com --> unsafe, filtered by Quad9
www.softica.fr --> unsafe, filtered by Quad9
www.siginlocalecountry.com --> unsafe, filtered by Strongarm
www.shoko-bussan.sakura.ne.jp --> unsafe, filtered by Quad9
www.secure17.000webhostapp.com --> unsafe, filtered by Strongarm
www.rixrax.com --> unsafe, filtered by Strongarm
www.residentstudents.org --> unsafe, filtered by Strongarm
www.registery-fanpages45.gq --> unsafe, filtered by Quad9
www.regiojardines.com --> unsafe, filtered by Strongarm
www.psicl.000webhostapp.com --> unsafe, filtered by Strongarm
www.prorammexico.com --> unsafe, filtered by Strongarm
-------------RESULT-------------
2/18 Safe
16/18 Blocked
Total time: 18.583242893218994
```
### domains.txt

The list of domains to lookup. Must be one per line.
