---
title: "My cybersecurity toolkit"
date: 2023-12-30T19:45:00+07:00
lastmod: 2025-05-09T19:45:00+07:00
showLastmod: true
draft: false
categories:
  - note
tags:
  - cybersecurity
keywords:
  - cybersecurity resources
  - cybersecurity tools
  - red team
  - blue team
  - purple team
---
## Overview

Ever since I started my journey into the world of cybersecurity, I've been compiling a list of resources and tools. It's my way of keeping track of everything I'm learning and organizing it in a way that makes sense to me. Think of it as my personal cybersecurity knowledge base.

The core principle I use is categorization by team and purpose. This means I first group tools and resources based on who primarily uses them (Red Team, Blue Team, or other security functions) and then, within those groups, I further organize them by what they are used for (vulnerability scanning, incident response, etc.).

This will be updated over time as I find new resources and tools.

## List

### Red Team
#### Reconnaissance (TA0043)
<ins>Desc:</ins> Gathering information for planning future operations.
* [`theHarvester`](https://github.com/laramies/theHarvester): OSINT tool for gathering  names, emails, IPs, subdomains, and URLs by using multiple public resources.
* [`hunter.io`](https://hunter.io/): Email harvesting.
* [`CF-Hero`](https://github.com/musana/CF-Hero): With multiple methods, used to discover Cloudflare origin IPs.
* [`URLCrazy`](https://github.com/urbanadventurer/urlcrazy): OSINT tool to generate and test domain variations for typosquatting, phishing, or brand protection research.
* [`gobuster`](https://github.com/OJ/gobuster): Brute-force tool to discover URIs, DNS subdomains, Virtual Hosts, cloud buckets, and TFTP servers.
* [`Nmap`](https://nmap.org/): Initial network scanning of external targets to identify live hosts and broadly check for open ports/services.

#### Initial Access (TA0001)
<ins>Desc:</ins> Trying to get into victim's network.
* [`cuddlephish`](https://github.com/fkasler/cuddlephish): Browser-in-the-Middle (BitM) framework for phishing attacks to bypass MFA and capture sessions.

#### Discovery (TA0007)
<ins>Desc:</ins> Trying to figure out victim's environment.
* [`Enum4Linux`](https://github.com/CiscoCXSecurity/enum4linux): Used for enumerating data from Windows and Samba hosts.
* [`Nmap`](https://nmap.org/): In-depth network mapping (internal/external) for detailed port/service/version/OS detection, vulnerability identification (NSE), and understanding network topology.

### Blue Team
#### Network Security
<ins>Desc:</ins> 
<ins>Tags:</ins> Network Intrusion Prevention (M1031), Filter Network Traffic (M1037), Network Segmentation (M1030)
* [`OPNsense`](https://opnsense.org/download/): FreeBSD-based, open-source, user-friendly firewall and routing platform.
* [`Snort`](https://www.snort.org/): Open-source Network Intrusion Prevention System (NIPS) and Intrusion Detection System (NIDS) that uses rule-based analysis of network traffic.

#### AppSec & DevSecOps
<ins>Desc:</ins> 
<ins>Tags:</ins> SSL/TLS Inspection (M1020), Exploit Protection (M1050)
* [`BunkerWeb`](https://github.com/bunkerity/bunkerweb): Nginx-based open-source Web Application Firewall (WAF).
* [`SafeLine`](https://github.com/chaitin/SafeLine): Open-source Web Application Firewall (WAF).

#### Endpoint Security
<ins>Desc:</ins> 
<ins>Tags:</ins> Behavior Prevention on Endpoint (M1040), Antivirus/Antimalware (M1049), Execution Prevention (M1038)
* [`ClamAV`](https://github.com/Cisco-Talos/clamav): Open source antivirus engine

#### Data Security
<ins>Desc:</ins> 
<ins>Tags:</ins> Data Loss Prevention (M1057), Data Backup (M1053)

#### Cloud Security
<ins>Desc:</ins> 
<ins>Tags:</ins>

#### Email Security
<ins>Desc:</ins> 
<ins>Tags:</ins>
* [`Sublime Platform`](https://github.com/sublime-security/sublime-platform): Open platform for detecting and preventing email attacks.
* [`DMARC-SPF-Checker`](https://github.com/fdzdev/DMARC-SPF-Checker): Analyzing DMARC and SPF records for a list of domains.
* [`MX Toolbox`](https://mxtoolbox.com/): Listing MX records for a domain.

#### Identity Security
<ins>Desc:</ins> 
<ins>Tags:</ins>
* [`Push Security`](https://pushsecurity.com): Browser-based ITDR platform protecting against phishing, AitM, credential abuse, and account takeover.

#### Incident Response & Automation
<ins>Desc:</ins> 
<ins>Tags:</ins>
* [`Shuffle`](https://github.com/Shuffle/Shuffle): Open-source Security Orchestration, Automation, and Response (SOAR) platform.
* [`ssdeep`](https://ssdeep-project.github.io/ssdeep/index.html): Computing and comparing fuzzy hashes (CTPH) to find similar malware.
* [`MalShare`](https://malshare.com/): Community malware repository with an API for sample submission, download, and querying (SHA256, YARA hits, etc.).
* [`MalwareBazaar (abuse.ch)`](https://bazaar.abuse.ch/): Malware repository and threat intelligence platform with extensive API for querying samples/indicators and providing threat feeds.
* [`Wireshark`](https://www.wireshark.org/): Network protocol analyzer for deep packet inspection, live capture, and offline analysis (e.g., PCAPs). Includes `TShark` command-line utility often used in automation.


### Others (Management, Purple Team)
#### Governance, Risk, and Compliance (GRC)
<ins>Desc:</ins> Focuses on frameworks, processes, and tools for establishing security policies, managing cyber risk, and ensuring compliance with external and internal requirements.  
<ins>Tags:</ins> User Training (M1017), Data Backup (M1053)
* [`Eramba`](https://github.com/eramba): Stable & feature-rich GRC platform.
* [`Comp AI`](https://github.com/trycompai/comp): New & under heavy-development GRC platform.
* [`Wizer`](https://www.wizer-training.com/): Security awareness training & phishing simulation.