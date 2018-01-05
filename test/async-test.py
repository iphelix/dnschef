import dns.resolver
import dns.query
import hashlib
import pyasn
import asyncio
import concurrent.futures
import time
import sys

# The database to correlate IP with ASN
asndb = pyasn.pyasn('ipasn_20171223.dat')

# Providers variable definition
Google = dns.resolver.Resolver()
Strongarm = dns.resolver.Resolver()
Quad9 = dns.resolver.Resolver()
SafeDNS= dns.resolver.Resolver()
ComodoSecure= dns.resolver.Resolver()
NortonConnectSafe= dns.resolver.Resolver()

# Sets IP address and name of each DNS providers
Google.nameservers = ['8.8.8.8', '8.8.4.4']
Google.Name = "Google"
Quad9.nameservers = ['9.9.9.9', '149.112.112.112']
Quad9.Name = "Quad9"
Strongarm.nameservers = ['54.174.40.213', '52.3.100.184']
Strongarm.Name = "Strongarm"
SafeDNS.nameservers = ['195.46.39.39', '195.46.39.40']
SafeDNS.Name = "SafeDNS"
ComodoSecure.nameservers = ['8.26.56.26', '8.20.247.20']
ComodoSecure.Name = "ComodoSecure"
NortonConnectSafe.nameservers = ['199.85.126.30', '199.85.127.30'] 
NortonConnectSafe.Name = "NortonConnectSafe"

# Query a provider and verify the answer
async def Query(domain,DnsResolver,asn_baseline,hash_baseline):
	try:		
		#Get the A record for the specified domain with the specified provider
		Answers = DnsResolver.query(domain, "A")		
		
	#Domain did not resolve
	except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):  
		 return [False, DnsResolver.Name]
	
	#List of returned IP	
	Arecords = []											
	for rdata in Answers:
		Arecords.append(rdata.address)
		
	#Compare the answer with the baseline to see if record(s) differ			
	if hashlib.md5(str(sorted(Arecords)).encode('utf-8')).hexdigest() != hash_baseline.hexdigest(): 
	
		#Record(s) differ, checking if the first one is in the same BGP AS								    
		if(asndb.lookup(sorted(Arecords)[0])[0] != asn_baseline):									
			 return [False, DnsResolver.Name]
			 
	#Domain is safe		 
	return [True, DnsResolver.Name]

# Creates the parallels tasks
async def main(domain,asn_baseline,hash_baseline):
	Providers = [Strongarm, NortonConnectSafe, ComodoSecure, Quad9, SafeDNS]
	with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
		tasks = [
			asyncio.ensure_future(Query(domain, Providers[i],asn_baseline,hash_baseline))
			for i in range(len(Providers))
		]
	   
		for response,provider in await asyncio.gather(*tasks):
			#One DNS provider in the function 'Query' returned False, so the domain is unsafe
			if response == False:		
				return [False, provider]
			pass
			
		#Function 'Query' never returned False at this point, the domain is safe
		return [True, provider]					
		
# Create the loop			
def loop(domain,asn_baseline,hash_baseline):
	loop = asyncio.get_event_loop()
	result = loop.run_until_complete(main(domain,asn_baseline,hash_baseline))
	
	# return is received, let's close the objects
	loop.run_until_complete(loop.shutdown_asyncgens())			
	return result
	
#Establish a baseline with Google Public DNS and call function "loop"
def lauch(domain):	
	hash_baseline = hashlib.md5()
	try:
			#Lookup the 'A' record(s)
			Answers_Google = Google.query(domain, "A") 		
			
	#Domain did not resolve		
	except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):  
			 return [False, Google.Name]
			 
	# Contain the returned A record(s)		 
	Arecords = []											
	for rdata in Answers_Google: 
		Arecords.append(rdata.address)
	
	#Looking the ASN of the first A record (sorted)
	asn_baseline = asndb.lookup(sorted(Arecords)[0])[0]	
	
	#MD5 Fingerprint of the anwser is the sorted list of A record(s)
	#Because of the round-robin often used in replies.
	#Ex. NS1 returns IP X,Y and NS2 returns IP Y,X
	hash_baseline.update(str(sorted(Arecords)).encode('utf-8')) 
	
	return loop(domain,asn_baseline,hash_baseline)
		

def usage(code=0):
    print('Usage: async-check.py list-domains.txt')
    exit(code)

if len(sys.argv) != 2:
    usage(1)

domains_file = sys.argv[1]

# Reading domains to lookup into the file
domains = []
with open(domains_file) as file:
    for line in file: 
        domains.append(line)

# Loop created to test the program with the list of malicious domains provided
i=0
nb_safe=0
nb_blocked=0
start = time.time()
while i<len(domains): 
	safe = False
	safe,Provider = lauch(domains[i])
	
	if(safe):
		print (domains[i].rstrip('\n') , "--> safe") 
		nb_safe+=1
	else:
		print (domains[i].rstrip('\n') , "--> unsafe, filtered by" , Provider)
		nb_blocked+=1	
	i+=1
	
print("-------------RESULT-------------")
print(str(nb_safe) + "/" + str(len(domains)) +  " Safe")
print(str(nb_blocked) + "/" + str(len(domains)) + " Blocked")
end = time.time()  
print("Total time: {}".format(end - start))  
