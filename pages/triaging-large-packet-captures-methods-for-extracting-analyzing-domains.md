---
layout: page
title: Triaging Large Packet Captures - Methods for Extracting & Analyzing Domains
description: Triaging Large Packet Captures - Methods for Extracting & Analyzing Domains
---

In the recent post [Triaging Large Packet Captures - 4 Key TShark Commands to Start Your Investigation](https://401trg.github.io/triaging-large-packet-captures-4-key-tshark-commands-to-start-your-investigation) I discussed some areas to begin investigating a large packet capture.  Generally when confronted with a large PCAP with unknown behavior in it we want to start whittling away chunks to surface areas to focus our analysis.  As a general strategy it's important to understand the infrastructure used in the PCAP as well as the protocols that are being used.  In this post we will focus on examining infrastructure by extracting domains from the PCAP.  We will also show how these domains can be compared against the Cisco Umbrella Popularity lists.

As previously discussed a great starting point for extracting domains is to use the TShark command:

```bash
tshark -q -r <pcap> -z hosts 
```
```bash
# TShark hosts output
#
# Host data gathered from <pcap>

115.85.68.215	kllserver.serveftp.com
173.194.67.106	www.google.com
119.160.247.124	ns5.yahoo.com
173.194.67.104	www.google.com
173.231.54.69	europd.ddns.info
74.125.95.106	www2.l.google.com
74.125.95.104	www2.l.google.com
...
```
*Figure 1. TShark hosts sample output.*


This command will produce a list of IP addresses and domains.  The bulk of this data is derived from DNS responses in which a domain is resolved to an IP address.  The IP addresses in the output are the resolution for the corresponding domains seen in a DNS response.  However it doesn’t mean that the IP address is involved in any of the conversations in the PCAP, it was just seen as a resolution in a DNS response.  For the most part this query gets us the bulk of what we are looking for, however there are some nuances to this and other places to find additional domains.  For example in the host lists you may have hostnames and IPs that weren’t directly queried, but were rather the result of a CNAME response to your original query.  This may happen when you query the A record for www.example.com and in the response you get www2.example.com as the CNAME and www2.example.com resolves to a given IP address.  In the hosts output you would only see www2.example.com and its corresponding IP address, with no evidence of the original lookup.  Additionally you may want to know domains that aren’t expected to resolve, such as a TXT record involved in DNS tunneling.  If you want to know all the domains that were queried you will need to extract from the DNS queries themselves.  

## Extracting From DNS Queries 

To extract all the content from the name portion of a DNS query use the following command:

```bash
tshark -q -r <pcap> -T fields -e dns.qry.name
```

This will output all query names from any traffic identified as DNS in the PCAP.  The output can be cleaned up a bit by focusing on queries only and ignore responses (remove the identical queries in the DNS response) by using the following:

```bash
tshark -q -r <pcap> -T fields -e dns.qry.name -Y "dns.flags.response eq 0"
```

An important caveat here is that you may get some garbage output from this query if there are any malformed DNS packets or traffic misidentified as DNS.  You will likely need to do a little cleaning up of the output to focus on only unique names queried.  If you are using bash it can be handy to remove empty lines with sed, sort the output, and then grab only unique lines like so:

```bash
tshark -q -r <pcap> -T fields -e dns.qry.name -Y "dns.flags.response eq 0" | sed '/^$/d' | sort | uniq
```

Additionally you can add the `-c` option onto `uniq` to get a count of occurrences then re-sort. 

```bash
1 www.usatoday.com
1 www.youtube.com
2 crl.usertrust.com
2 google.com
2 home.live.com
2 login.live.com
2 mail.live.com
2 nasa.usnewssite.com
3 www.gami1.com
4 europd.ddns.info
4 www.microsoft.com
5 www.google.com
6 www.download.windowsupdate.com
...
```
*Figure 2. Extracting DNS query names, sorting, and counting.* 

## Extracting from HTTP Host Headers

Another source to examine hostnames from is HTTP. It's helpful to pull in this information since you may not have corresponding DNS traffic to these locations in your packet capture.  The following command grabs the contents of the HTTP Host field, then removes blank lines and duplicates:

```bash
tshark -q -r <pcap> -T fields -e http.host | sed '/^$/d' | sort | uniq
```

```bash
199.192.156.134:443
239.255.255.250:1900
61.178.77.169:84
crl.comodoca.com
crl.microsoft.com
crl.usertrust.com
download.comodo.com
downloads.comodo.com
...
```
*Figure 3. Extracting hostnames from HTTP host field.*

Our main focus here has been on domains, but it's important to note that you may get IP addresses and ports in your output.  

## Using Cisco Umbrella List to Examine Extracted Hostnames

Once domains have been extracted from your PCAP you can begin identifying well known domains and isolating suspicious ones. For this task I like to use the [Cisco Umbrella Popularity Lists](http://s3-us-west-1.amazonaws.com/umbrella-static/index.html). Using the Top 1M list and a simple Python script you rank all the domains in your list according to their popularity in the Cisco Umbrella list. When searching for leads I like to focus on domains not found in the list. Below is the output from a [python script](https://github.com/401trg/utilities/blob/97f7e5526beee7059dad8a58eb868c6fe5866620/popularDomains.py) found on our github that takes a list of domains and checks it against the Top 1M list.

```bash
*** Domains Not Found in Top 1 Million ***
lookquery.info
mickeypluto.info
nasa.usnewssite.com
re.policy-forums.org
shittway.zapto.org:336
vcvcvcvc.dyndns.org
…

*** Domains Found in Top 1 Million ***
Rank - Domain
4 - www.google.com
64 - crl.microsoft.com
432 - www.microsoft.com
508 - crl.comodoca.com
1119 - crl.usertrust.com
4933 - www.download.windowsupdate.com
8873 - www.live.com
16075 - download.comodo.com
563265 - stats1.update.microsoft.com
...
```
*Figure 4.  Output from comparing domains to Cisco Top 1M list.*

Note that we are checking for exact matches here.  If you are overwhelmed with a bunch of domains not found in the list it may be worth searching on partial matches then seeing what's left over.  Additionally you could use the top TLD list to surface domains that have unusual TLDs.

## Next Steps

In this blog post we discussed three main ways of extracting domains from a PCAP, using TShark’s host output, extracting names from DNS queries, and extracting from HTTP host headers.  This will produce a fairly comprehensive view of the domains associated with your PCAP.  This information can be used to surface suspicious domains as well as trim traffic associated with non-suspicious domains. In future blog posts we will discuss methods for further analyzing suspicious domains.

*Written by James Condon, Director of Threat Research, ProtectWise.*
