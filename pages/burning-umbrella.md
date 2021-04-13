Burning Umbrella

---
layout: page
title: Burning Umbrella
description: Burning Umbrella
---

> ## An Intelligence Report on the Winnti Umbrella and Associated State-Sponsored Attackers

Key Judgements
 
- We assess with high confidence that the Winnti umbrella is associated with the Chinese state intelligence apparatus, with at least some elements located in the Xicheng District of Beijing.
- A number of Chinese state intelligence operations from 2009 to 2018 that were previously unconnected publicly are in fact linked to the Winnti umbrella.
- We assess with high confidence that multiple publicly reported threat actors operate with some shared goals and resources as part of the Chinese state intelligence apparatus.
- Initial attack targets are commonly software and gaming organizations in the United States, Japan, South Korea, and China. Later stage high profile targets tend to be politically motivated or high value technology organizations. 
- The Winnti umbrella continues to operate highly successfully in 2018. Their tactics, techniques, and procedures (TTPs) remain consistent, though they experiment with new tooling and attack methodologies often. 
- Operational security mistakes during attacks have allowed us to acquire metrics on the success of some Winnti umbrella spear phishing campaigns and identify attacker locations with high confidence.
- The theft of code signing certificates is a primary objective of the Winnti umbrella’s initial attacks, with potential secondary objectives based around financial gain.

## Report Summary


The purpose of this report is to make public previously unreported links that exist between a number of Chinese state intelligence operations. These operations and the groups that perform them are all linked to the Winnti umbrella and operate under the Chinese state intelligence apparatus. Contained in this report are details about previously unknown attacks against organizations and how these attacks are linked to the evolution of the Chinese intelligence apparatus over the past decade. Based on our findings, attacks against smaller organizations operate with the objective of finding and exfiltrating code signing certificates to sign malware for use in attacks against higher value targets. Our primary telemetry consists of months to years of full fidelity network traffic captures. This dataset allowed us to investigate active compromises at multiple organizations and run detections against the historical dataset, allowing us to perform a large amount of external infrastructure analysis. 
Background


The Winnti umbrella and closely associated entities has been active since at least 2009, with some reports of possible activity as early as 2007. The term "umbrella" is used in this report because current intelligence indicates that the overarching entity consists of multiple teams/actors whose tactics, techniques, and procedures align, and whose infrastructure and operations overlap. We assess that the different stages of associated attacks are operated by separate teams/actors, however in this report we will show that the lines between them are blurred and that they are all associated with the same greater entity. The Winnti and Axiom group names were created by Kaspersky Lab and Symantec, respectively, for their 2013/2014 reports on the original group. The name “Winnti” is now primarily used to refer to a custom backdoor used by groups under the umbrella. Multiple sources of public and private threat intelligence have their own names for individual teams. For example, LEAD is a common alias for the group targeting online gaming, telecom, and high tech organizations. Other aliases for groups related include BARIUM, Wicked Panda, GREF, PassCV, and others. This report details how these groups are linked together and serve a broader attacker mission. The many names associated with actors in the greater intelligence mission are due to the fact that they are built on telemetry of the intelligence provider which is typically unique and dependent on their specific dataset. This report focuses heavily on networking related telemetry. 

We assess with high confidence that the attackers discussed here are associated with the Chinese state intelligence apparatus. This assessment is based on attacker TTPs, observed attack infrastructure, and links to previously published intelligence. Their operations against gaming and technology organizations are believed to be economically motivated in nature. However, based on the findings shared in this report we assess with high confidence that the actor’s primary long-term mission is politically focused. It’s important to note that not all publicly reported operations related to Chinese intelligence are tracked or linked to this group of actors. However, TTPs, infrastructure, and tooling show some overlap with other Chinese-speaking threat actors, suggesting that the Chinese intelligence community shares human and technological resources across organizations. We assess with medium to high confidence that the various operations described in this report are the work of individual teams, including contractors external to the Chinese government, with varying levels of expertise, cooperating on a specific agenda. 

In 2015 the People’s Liberation Army of China (PLA) began a major reorganization which included the creation of the Strategic Support Force (SSF / PLASSF). SSF is responsible for space, cyber, and electronic warfare missions. Some of the overlap we observed from groups could potentially be related to this reorganization. Notably, key incident details below include attacker mistakes that likely reveal the true location of some attackers as the Xicheng District of Beijing. 


Tactics, Techniques, and Procedures (TTPs):
Though the TTPs of the attacking teams vary depending on the operation, their use of overlapping resources presents a common actor profile. Key interests during attacks often include the theft of code signing certificates, source code, and internal technology documentation. They also may attempt to manipulate virtual economies for financial gain. While unconfirmed, the financial secondary objective may be related to personal interests of the individuals behind the attacks.

Initial attack methods include phishing to gain entry into target organization networks. The group then follows with custom malware or publicly available offensive tooling (Metasploit/Cobalt Strike), and may use a number of methods to minimize their risk of being detected. Such techniques include a particular focus on “living off the land” by using a victim's own software products, approved remote access systems, or system administration tools for spreading and maintaining unauthorized access to the network.

We have observed incidents where the attacker used other victim organizations as a proxy for unauthorized remote access. In these cases, organization 1 had been compromised for a long period of time, and the attacker accessed victim organization 2 via the organization 1 network. 

Delivery and C2 domains routinely have subdomains which resemble target organizations. Additionally, their C2 domains are used across many targets, while subdomains tend to be created and removed quickly and are unique to a particular target or campaign. Also noteworthy is that the actors set their domains to resolve to 127.0.0.1 when not in use, similar to what was originally reported on by Kaspersky Lab (see below). 

The actor often uses TLS encryption for varying aspects of C2 and malware delivery. As noted in the “Infrastructure Analysis” section of this report, the actor primarily abuses Let’s Encrypt to sign SSL certificates. We also observed many cases in which self-signed certificates were used in attacks.

Overall, the Winnti umbrella and linked groups are lacking when it comes to operational security. However, some activities linked to these groups follow better operational security and infrastructure management approaches. This may be a clue to the division of responsibilities by team and skill level within the broader organization. 


Targets:
The Winnti umbrella and linked groups’ initial targets are gaming studios and high tech businesses. They primarily seek code signing certificates and software manipulation, with potential financially motivated secondary objectives. These targets have been identified in the United States, Japan, South Korea, and China.

Based on the infrastructure, links to previous reporting, and recently observed attacks, the broader organization’s main targets are political. Historically this has included Tibetan and Chinese journalists, Uyghur and Tibetan activists, the government of Thailand, and prominent international technology organizations.

One example of a politically focused lure by the Winnti umbrella and linked groups is an end of 2017 document titled “Resolution 2375 (2017) Strengthening Sanctions on DPR of KOREA” which is a malicious file associated with the C2 infrastructure described here - see MD5: 3b58e122d9e17121416b146daab4db9d. 
