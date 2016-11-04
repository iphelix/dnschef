def init():
   """Optional function to initialize plugin.
   """
   print "TestHandler initialized."

def handle(request,response):
   """Optional function called with the request and response that will be sent in 
      in response to the query. This is called within the DNSChef thread, so any 
      long precessing should be spawned into another thread.
      :param request: dnslib.DNSRecord for the request
      :param response: dnslib.DNSRecord for the response
      
      The return value from this function will be sent in response to the query.

   """
   print "in handle."
   print "---------------------------   request ----------------------------"
   print repr(request)
   print "---------------------------   response ----------------------------"
   print repr(response)
   return response
