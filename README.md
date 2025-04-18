# custom-dns-resolver

This is a custom dns resolver, made to retrieve the A record of a given domain. In this case, it was made to query the A record of a RBL like Spamhaus. Why? Because Spamhaus rejects queries made from an open resolver, and without using a custom DNS server, your query will fail against this specific RBL unless you are allowed to modify the system you are using, so in order to solve this issue here we find the A record making a query directly to the Root servers from IANA.
This solves the issue of relying in external solutions, like a proper DNS server like Technitium https://github.com/TechnitiumSoftware/DnsServer, instead you can just query to find out if a given IP is listed at spamhaus or any other RBL.

How to use it? Run the script and the IP in reverse + the RBL, example:
If the IP is 86.106.14.0 and the RBL to lookup is zen.spamhaus.org, then the command should be "python dns_resolver.py 0.14.106.86.zen.spamhaus.org"
Which if is listed, will print the following because spamhaus returns the special A record 127.0.0.x, an indicator that the IP is blacklisted :
"The IP address(es) for 0.14.106.86.zen.spamhaus.org is/are: 127.0.0.2, 127.0.0.9"


If it's not listed, then it will print 
"The record queried, 0.14.106.185.zen.spamhaus.org which is the IP 185.106.14.0, is not blacklisted in a RBL"

You can verify also by using Mxtoolbox or HetrixTools, just grab any random IP in the droplist of spamhaus:
https://www.spamhaus.org/drop/drop_v4.json
And then check it at Mxtoolbox or HetrixTools:
https://hetrixtools.com/blacklist-check/86.106.14.0
https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a86.106.14.0&run=toolpage
# custom-dns-resolver
# custom-dns-resolver
