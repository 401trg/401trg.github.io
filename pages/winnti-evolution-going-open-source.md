Winnti Evolution - Going Open Source

ProtectWise recently observed a burst of activity and change of tactics from an advanced actor group commonly referred to as “Winnti.” The purpose of this post is to share details of the group’s recent activity in an effort to assist the public in searching for related activity in their networks and preventing future attacks. 

About Winnti
The Winnti group has been active since roughly 2010. Significant previous research has been published on the group from a variety of sources, such as Kaspersky, Blue Coat, and TrendMicro. As far back as 2011, the group was detected attacking multiple video game studios, including some in South Korea and Japan, likely attempting to steal various in-game currencies and to compromise developers’ certificates and source code. 

Objectives:
Theft of digital certificates
Use of stolen certificates to sign malware
Theft of gaming source code and infrastructure details

TTPs:
Known Toolset: PIVY, Chopper, PlugX, ZxShell, Winnti
Phishing HR/recruiting emails for initial infection vector
CHM email file attachments containing malware
Use of GitHub for C2 communication

Targets:
Online video game organizations
Defense Sector
Internet Service Providers

Attribution:
Originating Location: China (high confidence)
Potential Aliases: Wicked Panda, APT17


Evolution of Winnti - Open source tools, and Mac OS targeting:
Within the Winnti campaigns observed by ProtectWise, the use of open source tooling was common. Specifically, the group has been utilizing the Browser Exploitation Framework (BeEF) and Metasploit Meterpreter. The use of open source tools by advanced actor groups has become increasingly common, as discussed by our colleagues in the industry. To the best of our knowledge this is a new technique for the Winnti group and we expect it to be used in future attacks. 

Also noteworthy are attempts to deliver JAR files containing macOS applications which have meterpreter functionality. In addition, victims running Windows were delivered MSI files which were built using a free EXE to MSI converter (http://www.exetomsi.com/).  
