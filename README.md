# JDMARC1_SDHUBBA_IT_360_Final_Project_Spring_2026

## Team Members
- Jacob Marcotte
- Steven Hubbard

## Network Forensics Software

Our Project aims to create a software that can capture network traffic and analyze it to find malware or some other irregular behavior. 
We are NOT creating a software that constantly analyzes network traffic as it appears; we just want to be able to take an image of network traffic and ues our software to examine it. 
We are still discussing which tools will be required for this assignment. We believe that Wireshark and TCP Dump might be useful tools for capturing network traffic for analysis. For Proxmox, we would like 2-3 VMs to simulate network traffic, where one of the VMs is a Kali Kinux VM. 

We are still searching for more software that we can use for our project. We will be conducting research into software that can help us in the near future. If you have any suggestions, please let us know. 

At this time, our plan is to create a packet sniffer that tracks packets within a network. Hashes are taken of the bodies of these packets, and are comparred to online databases of hashes that are associated with malware. If a hash matches the hash of a known malware packet, an alert is sent to a user. AI is then used to summarize the details of the malware in a readable format for the user. 
