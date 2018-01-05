Query Quad9, Strongarm, SafeDNS, ComodoSecure and NortonConnectSafe public DNS resolvers in parallels to verify if the domain is safe.
If a provider returns either NXdomain, Nodata or a sinkholed IP address for a specified domain, it  will end other queries and return False (domain unsafe).
If all providers correctly resolve the domain, it will be considered safe.

You can add as many threat blocking DNS providers as you want to the script, those 5 providers were choose only for the POC.

## Setup

### Python packages
* [dnspython](https://pypi.python.org/pypi/dnspython)
* [asyncio](https://docs.python.org/3/library/asyncio.html)
* [pyasn](https://github.com/hadiasghari/pyasn)
