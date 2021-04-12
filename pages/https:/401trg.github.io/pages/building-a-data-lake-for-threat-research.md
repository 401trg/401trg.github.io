## Building a Data Lake for Threat Research

Not long ago the thought of storing every DNS query, SSL certificate, HTTP transaction, and netflow record on a traditional enterprise network for an unlimited period of time sounded ludicrous. Even harder to imagine is using that data to conduct threat research or hunting in a cost-effective and time-efficient way. However, today cloud computing enables the retention and search of full fidelity network artifacts at a massive scale. There are a number of technologies available that make this analyst’s dream possible. In this blog post we will discuss a method of conducting threat research on network metadata at scale using Amazon S3, Apache Parquet, Spark, and Zeppelin. 

### Important Network Artifacts to Extract and Store  

There are endless possibilities when it comes to extracting important metadata from the network. It's important to prioritize which artifacts will give you the biggest impact. In our case, we have found the following to be most beneficial:

- HTTP transactions
- SSL certificates & handshake details
- DNS Queries
- Files extracted from popular protocols
- SMTP/IMAP/POP headers and content
- SMB Metadata
- Netflow Records

As you can imagine, storing all this data can get quite large on a single enterprise network and even larger across multiple networks. To give you a sense of how big this data can get, on a given day we see billions of new conversations resulting in a “netflow” record (ip, port, bytes sent and received, protocol, geo information, device tracking, and directionality). We see several million updates to these records throughout the day. Additionally, after extracting individual attributes for the protocols mentioned above we add several billion extracted features. If you need to prioritize which attributes to start with, consider where the data is being collected on the network and what critical segments are monitored. For monitoring typical ingress/egress on an enterprise network for malware communications, I would recommend prioritizing netflow records, DNS queries, and SSL attributes.

### Storing the Data

The data storage process begins when sensors replay network traffic (make a copy of relevant packets to ship back) and generate netflow records on a given network. This traffic is processed in a central hub where features (attributes of a given protocol) are extracted from the collected PCAP. The features and netflow records are then converted to parquet and finally stored in Amazon S3 (the data lake). 

The data lake post-processors monitor newly written features and netflow records to perform a number of aggregation operations in batches. Important portions of the feature (such as domains in a DNS query) are indexed in fast-to-process data structures for quicker searching. This allows searching on certain fields to be 150-500 times faster than searching the raw data. This type of indexing is critical to cost-saving given the amount of data and length of storage we work with. Reading a year of data with our standard Amazon EMR system types can take days on a 40-node Spark cluster, costing thousands of dollars; our indexing allows us to do the same processing on a quarter of the nodes in less than 1% of the runtime. In addition to indexing, we flatten certain parts of the data to make it more user-friendly as well as add aggregation for items that require frequent counting. Certain problems require the creation of long-spanning aggregations, and since running these from source can be time-consuming and expensive, we create aggregates based on time slices on the fly. 

### Accessing the Data

401TRG tends to have a lot of ad hoc data analysis needs. With Spark we can use SQL interfaces for querying the data. Once we understand the types of queries that are most common, we can automate ETL (Extract, Transform and Load) or MR (MapReduce) workloads to produce simplified structures that are easier to work with. Additionally, since we repeat certain types of queries and share query logic with other team members, we use Zeppelin to create web-based notebooks that we can easily share and store.

During exploratory data analysis cost awareness is important. However, it isn’t always obvious which types of queries end up being more computationally expensive than others. One thing we do to help mitigate cost issues is create systems for on-demand resource allocation as opposed to having systems continually running and waiting for ad hoc tasks. We built a system internally to allow users to spin up and configure EMR clusters via a UI. Each cluster is preloaded with Zeppelin and Spark SQL (along with scala-spark and pyspark).

Using Zeppelin we can create a repo of notebooks to save some common SQL queries we use to access this data. Doing this via notebooks allows 401TRG to share and reuse common query syntax. It also allows us to create hunting playbooks that can be run periodically to hunt down malicious behavior. 

### Hunting

Now that we have a data lake and an easy way to access the data, where do we start our hunting process?

#### Indicator Searching

First and foremost, searching for various types of indicators can prove very valuable. Often you will come across new indicators in the course of your daily workflow. These could come from open source intelligence being shared or internal research. Either way, it's always handy to be able to search for IPs, domains, URLs, hashes, SSL certificates, etc. Given that the data lake is designed to retain data for a very long period of time, this can make searches for high value IOCs very powerful. 
 
#### IP Address Monitoring

In the CrowdStrike Cyber Intrusion Services Casebook 2017, remote access is one of the predominant attack vectors they encountered. Using a data lake you can query the remote IP addresses associated with any RDP or VPN connections to your environment. You can tailor your queries to look for established sessions or brute force attempts. These destinations can be fact checked against what is allowed in your environment to identify potentially malicious connections.

This should also be applied to DNS traffic. In general your outbound DNS traffic should be confined to a handful of servers. By regularly monitoring remote IPs queried, you should be able to flag something that forces a host to resolve a query (or tunnel traffic) to an irregular destination. Once curated and massaged, these types of techniques should be automated and integrated into your detection tools.

#### Surfacing Outliers

A simple but powerful technique we use is counting unique instances of interesting attributes. The idea here is to learn what is frequent and what is not. This works best when variance in the attribute is low, but that is not always the case. Below are a few examples of interesting attributes to examine:

1. User-Agent strings
2. HTTP header names
3. SSL certificates
    - Common Name
    - Subject
    - Issuer
    - Serial
    - JA3 Fingerprints
4. DNS resource records (RRs)
    - Name 
    - TTL
    - Record Type
    - Class
4. Protocol Counts
5. SMTP header names

### Data Stacking

Building on the idea of counting unique attributes, we can expand to counting groups of attributes. This method, sometimes referred to as Data Stacking, is commonly used to hunt for suspicious processes on a given host as described in this blog post by FireEye. This method can also be applied to many network attributes. Below are some examples of attributes to group and count:

1. **HTTP header names:** Grouping by the order of header names should identify transactions where unusual header names or header ordering occurs. 
2. **DNS RRs:** This one may be a little tricky due to volume, but examining combinations such as the following can help hunt down suspicious DNS queries:
    - Name and record type
    - Name and TTL
    - Record Type and TTL
3. **SSL Certificates:** Grouping common name, subject, and issuer can identify poorly crafted certificates meant to imitate authentic ones. Grouping validity dates can identify certificates that were created in an unusual way. Additionally, grouping JA3 fingerprints with destination ports or specific attributes of the certificate can prove very interesting.

### Wrapping Up

In this blog post we presented a method to store and query a data lake of network artifacts using widely available technologies. We also discussed a handful of hunting techniques that can benefit from the long-term storage of network data. For teams with large data volumes, an easily accessible data lake can significantly improve your threat hunting/detection capabilities. We’ve found this particularly useful for researching and validating new detection hypothesises as well as conducting investigations. We hope you find this information valuable as you build out or maintain your own data lake.

*Written in collaboration with Matt Anthony, Director of Data Science, ProtectWise and Justin Miller, Manager of Threat Engineering, ProtectWise.*

