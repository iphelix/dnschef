

DNSMasterChef is a POC based on the original project DNSChef. I integrated my project [Dns-online-filter](https://github.com/NavyTitanium/Dns-online-filter) to it so it will only forward safe domains, while spoofing unsafe domains.

It will verify 'A' queries and forward directly all other type of requests. The script listen locally on port #5353, so you can forward BIND requests to it.

## Running DNSMasterChef
```
    # ./dnschef.py

    [*] DNSChef started on interface: 127.0.0.1 
    [*] Using the following nameservers: 8.8.8.8
    [*] No parameters were specified. Running in full proxy mode
```
