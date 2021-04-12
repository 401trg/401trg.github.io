An Introduction to SMB for Network Security Analysts

Of all the common protocols a new analyst encounters, perhaps none is quite as impenetrable as Server Message Block (SMB). Its enormous size, sparse documentation, and wide variety of uses can make it one of the most intimidating protocols for junior analysts to learn. But SMB is vitally important: lateral movement in Windows Active Directory environments can be the difference between a minor and a catastrophic breach, and almost all publicly available techniques for this movement involve SMB in some way. While there are numerous guides to certain aspects of SMB available, I found a dearth of material that was accessible, thorough, and targeted towards network analysis. The goal of this guide is to explain this confusing protocol in a way that helps new analysts immediately start threat hunting with it in their networks, ignoring the irrelevant minutiae that seem to form the core of most SMB primers and focusing instead on the kinds of threats an analyst is most likely to see. This guide necessarily sacrifices completeness for accessibility: further in-depth reading is provided in footnotes. There are numerous simplifications throughout to make the basic operation of the protocol more clear; the fact that they are simplifications will not always be highlighted. Lastly, since this guide is an attempt to explain the SMB protocol from a network perspective, the discussion of host based information (windows logs, for example) has been omitted. 

## The Basics

At its most basic, SMB is a protocol to allow devices to perform a number of functions on each other over a (usually local) network. SMB has been around for so long and maintains so much backwards compatibility that it contains an almost absurd amount of vestigial functionality, but its modern core use is simpler than it seems. For the most part, today SMB is used to map network drives, send data to printers, read and write remote files, perform remote administration, and access services on remote machines. 

SMB runs directly over TCP (port 445) or over NetBIOS (usually port 139, rarely port 137 or 138). To begin an SMB session, the two participants agree on a dialect, authentication is performed, and the initiator connects to a ‘tree.’ For most intents and purposes, the tree can be thought of as a network share. The PCAP below, shown in Wireshark, demonstrates a simple session setup and tree connect. In this case, the machine 192.168.10.31 is connecting to the “c$” share (equivalent to the C:\ drive) on the 192.168.10.30 machine, which is called “admin-pc.” 

![Image of Yaktocat](assets/images/smb_image_1.png)
![Image of Yaktocat](assets/images/smb_image_2.png)
![Image of Yaktocat](assets/images/smb_image_3.png)
![Image of Yaktocat](assets/images/smb_image_4.png)
![Image of Yaktocat](assets/images/smb_image_5.png)
![Image of Yaktocat](assets/images/smb_image_6.png)
![Image of Yaktocat](assets/images/smb_image_7.png)
![Image of Yaktocat](assets/images/smb_image_8.png)
![Image of Yaktocat](assets/images/smb_image_9.png)
![Image of Yaktocat](assets/images/smb_image_10.png)
![Image of Yaktocat](assets/images/smb_image_11.png)

