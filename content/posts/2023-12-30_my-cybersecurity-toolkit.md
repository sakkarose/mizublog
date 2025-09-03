---
title: "My cybersecurity toolkit"
date: 2023-12-30T19:45:00+07:00
lastmod: 2025-09-03T19:45:00+07:00
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
<ins>Description:</ins> Gathering information for planning future operations.
* [`Bjorn`](https://github.com/infinition/Bjorn): Pwnagotchi-like tool for network scanning, vulnerability assessment.
* [`CF-Hero`](https://github.com/musana/CF-Hero): With multiple methods, used to discover Cloudflare origin IPs.
* [`cloudscraper`](https://github.com/VeNoMouS/cloudscraper): Python module to bypass Cloudflare's anti-bot page (IUAM), enabling scraping and crawling of websites protected by these measures.
* [`Creepy`](https://github.com/ilektrojohn/creepy): OSINT tool that gathers and maps geolocation information from online sources (e.g., social media, photo metadata).
* [`dig`](https://linux.die.net/man/1/dig): Advanced command-line tool for DNS interrogation, offering more detailed and flexible queries than nslookup.
* [`dnsdumpster.com`](https://dnsdumpster.com/): Online service for finding DNS records and subdomains related to a domain to help map the attack surface.
* [`Evil-M5Project`](https://github.com/7h30th3r0n3/Evil-M5Project): ESP32/M5Core2-based offensive toolkit for Wi-Fi attacks (Rogue AP, Evil Twin, deauth, Karma), network attacks, BadUSB, Bluetooth attacks, and C2, aimed at gaining access and control.
* [`GeoSpy`](https://github.com/atiilla/geospy): Python tool using an AI service (Graylark) to identify the geographical location where photos were taken.
* [`gobuster`](https://github.com/OJ/gobuster): Brute-force tool to discover URIs, DNS subdomains, Virtual Hosts, cloud buckets, and TFTP servers.
* [`hcxdumptool`](https://github.com/ZerBea/hcxdumptool): Tool for capturing WiFi WPA/WPA2 handshakes and PMKIDs from wireless networks for subsequent cracking attempts.
* [`hunter.io`](https://hunter.io/): Email harvesting.
* [`Nessus`](https://www.tenable.com/products/nessus): An industry-standard vulnerability scanner for identifying vulnerabilities, misconfigurations, and malware on network assets.
* [`Nmap`](https://nmap.org/): Initial network scanning of external targets to identify live hosts and broadly check for open ports/services.
* [`nslookup`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/nslookup): Standard command-line tool for querying DNS to obtain domain name or IP address mapping information.
* [`OpenVAS`](https://github.com/greenbone/openvas-scanner): A full-featured vulnerability scanner that identifies security issues in servers and network devices.
* [`Osintgram`](https://github.com/amir-hosseinpour/Osintgram-fixed): OSINT tool for collecting, analyzing, and running reconnaissance on Instagram profiles.
* [`PhoneInfoga`](https://github.com/sundowndev/phoneinfoga): Advanced OSINT tool for scanning international phone numbers to gather associated information (carrier, line type, owner clues, social media presence, etc.).
* [`Pwnagotchi`](https://github.com/jayofelony/pwnagotchi): Raspberry Pi-based tool (using bettercap) for automatically capturing WPA/WPA2 handshakes and PMKIDs for offline cracking.
* [`RustScan`](https://github.com/RustScan/RustScan): A high-speed port scanner for quickly finding all open ports on a target.
* [`Sherlock`](https://github.com/sherlock-project/sherlock): OSINT tool to hunt down social media and other online accounts by username across numerous platforms.
* [`shodan.io`](https://www.shodan.io/): Search engine for discovering internet-connected devices and services, identifying exposed systems, IoT, and operational technology.
* [`theHarvester`](https://github.com/laramies/theHarvester): OSINT tool for gathering  names, emails, IPs, subdomains, and URLs by using multiple public resources.
* [`URLCrazy`](https://github.com/urbanadventurer/urlcrazy): OSINT tool to generate and test domain variations for typosquatting, phishing, or brand protection research.
* [`Wappalyzer`](https://github.com/developit/wappalyzer): A browser extension and utility that identifies the technologies used on websites, such as frameworks, CMS, and analytics tools.
* [`viewdns.info`](https://viewdns.info/): A web-based collection of network tools for DNS, IP, and domain reconnaissance.
* [`whois`](https://www.whois.com/whois/): Command-line and web utility to query registration data for domains and IP addresses (owner, registrar, contact info).

#### Initial Access (TA0001)
<ins>Description:</ins> Trying to get into victim's network.
* [`CATSploit`](https://github.com/catsploit/catsploit): Automated penetration testing tool that gathers information, scores, and selects attack techniques, then executes them via Metasploit to compromise targets.
* [`cuddlephish`](https://github.com/fkasler/cuddlephish): Browser-in-the-Middle (BitM) framework for phishing attacks to bypass MFA and capture sessions.
* [`Evil-M5Project`](https://github.com/7h30th3r0n3/Evil-M5Project): ESP32/M5Core2-based offensive toolkit for Wi-Fi attacks (Rogue AP, Evil Twin, deauth, Karma), network attacks, BadUSB, Bluetooth attacks, and C2, aimed at gaining access and control.
* [`Evilginx`](https://github.com/kgretzky/evilginx2): Man-in-the-middle attack framework for phishing credentials and session cookies to bypass 2FA.
* [`EvilnoVNC`](https://github.com/JoelGMSec/EvilnoVNC): Phishing platform using a real browser over noVNC to bypass 2FA, capture credentials, sessions, and access browser profile data.
* [`metasploit-framework`](https://github.com/rapid7/metasploit-framework): A comprehensive penetration testing platform for developing, testing, and executing exploits against remote targets.
* [`Modlishka`](https://github.com/drk1wi/Modlishka): HTTP reverse proxy for advanced phishing attacks; facilitates 2FA bypass by capturing credentials and session cookies.
* [`Muraena`](https://github.com/muraenateam/muraena): Reverse proxy for automating phishing and post-phishing activities, facilitating credential and session capture.
* [`Powershell-to-Ducky-Converter`](https://github.com/I-Am-Jakoby/Powershell-to-Ducky-Converter): Converts PowerShell scripts into Ducky Script for BadUSB (e.g., USB Rubber Ducky) payloads.
* [`Wifiphisher`](https://github.com/wifiphisher/wifiphisher): Rogue Access Point framework for Wi-Fi MitM attacks, phishing credentials (network keys, web logins), and malware deployment.

#### Execution (TA0002)
<ins>Description:</ins> Trying to run malicious code.
* [`Burp Suite`](https://portswigger.net/burp/communitydownload): An integrated platform for web application security testing, used for intercepting, analyzing, and manipulating web traffic.
* [`PowerShell-for-Hackers`](https://github.com/I-Am-Jakoby/PowerShell-for-Hackers): A collection of PowerShell scripts for offensive tasks like reverse shells, keylogging, and payload delivery.

#### Defense Evasion (TA0005)
<ins>Description:</ins> Trying to avoid being detected
* [`UserAgent-Switcher`](https://github.com/ray-lothian/UserAgent-Switcher): A browser extension for spoofing the User-Agent string, which can help bypass agent-based access controls.

#### Credential Access (TA0006)
<ins>Description:</ins> Trying to steal account names and passwords.
* [`aircrack-ng`](https://www.aircrack-ng.org/): A set of tools for auditing wireless networks, including packet capturing and cracking WEP/WPA/WPA2 keys.
* [`Bjorn`](https://github.com/infinition/Bjorn): Pwnagotchi-like tool for brute-force attacks (FTP, SSH, SMB, etc.), and data exfiltration.
* [`Ciphey`](https://github.com/bee-san/Ciphey): Automated decryption/decoding tool using AI for cipher detection.
* [`crackstation.net`](https://crackstation.net/): Online hash cracking service using massive pre-computed rainbow tables.
* [`cuddlephish`](https://github.com/fkasler/cuddlephish): Browser-in-the-Middle (BitM) framework for phishing attacks to bypass MFA and capture sessions.
* [`Evilginx`](https://github.com/kgretzky/evilginx2): Man-in-the-middle attack framework for phishing credentials and session cookies to bypass 2FA.
* [`EvilnoVNC`](https://github.com/JoelGMSec/EvilnoVNC): Phishing platform using a real browser over noVNC to bypass 2FA, capture credentials, sessions, and access browser profile data.
* [`hashcat`](https://github.com/hashcat/hashcat): Advanced password recovery and cracking tool supporting numerous hash types and attack modes, capable of GPU acceleration.
* [`hash-identifier`](https://github.com/blackploit/hash-identifier): A Python script to identify the type of hash algorithm used on a given hash.
* [`hcxtools`](https://github.com/ZerBea/hcxtools): Utilities to convert WiFi WPA/WPA2 packet captures into hash formats for cracking.
* [`Impacket`](https://github.com/fortra/impacket): Python toolkit for network protocol interaction, used for credential dumping and relay attacks.
* [`mimikatz`](https://github.com/ParrotSec/mimikatz): A powerful tool to extract plaintext passwords, hashes, and Kerberos tickets from memory on Windows systems.
* [`Modlishka`](https://github.com/drk1wi/Modlishka): HTTP reverse proxy for advanced phishing attacks.
* [`Muraena`](https://github.com/muraenateam/muraena): Reverse proxy for automating phishing and post-phishing activities.
* [`THC Hydra`](https://github.com/vanhauser-thc/thc-hydra): A fast network logon cracker for brute-forcing credentials against numerous protocols like SSH, FTP, and HTTP.
* [`Wifiphisher`](https://github.com/wifiphisher/wifiphisher): Rogue Access Point framework for Wi-Fi MitM attacks and phishing.
* [`wpa-sec.stanev.org`](https://wpa-sec.stanev.org/): Community-driven platform for distributed cracking of WPA/WPA2 PSKs.

#### Discovery (TA0007)
<ins>Description:</ins> Trying to figure out victim's environment.
* [`Enum4Linux`](https://github.com/CiscoCXSecurity/enum4linux): Used for enumerating data from Windows and Samba hosts.
* [`Nmap`](https://nmap.org/): In-depth network mapping (internal/external) for detailed port/service/version/OS detection, vulnerability identification (NSE), and understanding network topology.

#### Collection (TA0009)
<ins>Description:</ins> Trying to gather data of interest to their goal.
* [`EvilnoVNC`](https://github.com/JoelGMSec/EvilnoVNC): Phishing platform using a real browser over noVNC to bypass 2FA, capture credentials, sessions, and access browser profile data.

#### Command and Control (TA0011)
<ins>Description:</ins> Trying to communicate with compromised systems to control them.
* [`PingRAT`](https://github.com/umutcamliyurt/PingRAT): Remote Access Trojan (RAT) that uses ICMP packets for covert Command and Control (C2) traffic.

#### Impact (TA0040)
<ins>Description:</ins> Trying to manipulate, interrupt, or destroy your systems and data.
* [`MHDDoS`](https://github.com/MatrixTM/MHDDoS): A powerful DDenial of Service (DoS) attack script written in Python.
* [`slowloris`](https://github.com/gkbrk/slowloris): HTTP Denial of Service tool that exhausts a web server's connection pool by slowly sending headers.

### Blue Team
#### Network Security
<ins>Description:</ins> Monitoring network traffic, controlling access, and actively preventing intrusions.

<ins>Tags:</ins> Network Intrusion Prevention (M1031), Filter Network Traffic (M1037), Network Segmentation (M1030)

* [`OPNsense`](https://opnsense.org/download/): FreeBSD-based, open-source, user-friendly firewall and routing platform.
* [`Snort`](https://www.snort.org/): Open-source Network Intrusion Prevention System (NIPS) and Intrusion Detection System (NIDS) that uses rule-based analysis of network traffic.
* [`testmynids.org`](https://github.com/3CORESec/testmynids.org): Website and script framework for testing Network Intrusion Detection System (NIDS) detection capabilities against known malicious patterns.
* [`Nzyme`](https://github.com/nzymedefense/nzyme): Wireless Intrusion Detection System (WIDS) and network monitor for detecting unauthorized devices (WiFi, Bluetooth, wired), rogue APs, and wireless attacks.
* [`AC-Hunter`](https://www.activecountermeasures.com/ac-hunter-community-edition/): A threat hunting tool that analyzes network traffic data (from Zeek or other sources) to find beaconing Command and Control (C2) activity.
* [`RITA (Real Intelligence Threat Analytics)`](https://github.com/activecm/rita): Framework for detecting command and control (C2) communication (beaconing, DNS tunneling, etc.) through network traffic analysis of Zeek logs.
* [`Zeek`](https://zeek.org/): A powerful network analysis framework that goes beyond a traditional IDS, providing detailed, structured logs of all network activity (HTTP, DNS, SSL, etc.).

#### AppSec & DevSecOps
<ins>Description:</ins> Building security into applications, inspecting web traffic, and actively defending against exploits.

<ins>Tags:</ins> SSL/TLS Inspection (M1020), Exploit Protection (M1050)

* [`BunkerWeb`](https://github.com/bunkerity/bunkerweb): Nginx-based open-source Web Application Firewall (WAF).
* [`grype`](https://github.com/anchore/grype): Vulnerability scanner for container images and filesystems.
* [`OWASP ZAP`](https://www.zaproxy.org/): An open-source web application security scanner for finding vulnerabilities during development and testing.
* [`SafeLine`](https://github.com/chaitin/SafeLine): Open-source Web Application Firewall (WAF).
* [`Snyk`](https://snyk.io/): Developer security platform for finding and fixing vulnerabilities in code, dependencies, and containers.

#### Endpoint Security
<ins>Description:</ins> Monitoring endpoint activities, preventing malware infections, and actively blocking malicious code execution.

<ins>Tags:</ins> Behavior Prevention on Endpoint (M1040), Antivirus/Antimalware (M1049), Execution Prevention (M1038)

* [`ClamAV`](https://github.com/Cisco-Talos/clamav): Open source antivirus engine
* [`kernel-hardening-checker`](https://github.com/a13xp0p0v/kernel-hardening-checker): Tool for checking Linux kernel security hardening options (compile-time, boot-time, runtime) against best practices.

#### Data Security
<ins>Description:</ins> Identifying sensitive data, preventing its unauthorized loss, and actively ensuring its backup and recovery.

<ins>Tags:</ins> Data Loss Prevention (M1057), Data Backup (M1053)

#### Cloud Security
<ins>Description:</ins> Managing secure cloud configurations, protecting cloud workloads and data, and actively controlling access to cloud resources.

<ins>Tags:</ins>

#### Email Security
<ins>Description:</ins> Authenticating email senders, filtering out malicious content, and actively defending against email-based attacks.

<ins>Tags:</ins>

* [`Sublime Platform`](https://github.com/sublime-security/sublime-platform): Open platform for detecting and preventing email attacks.
* [`DMARC-SPF-Checker`](https://github.com/fdzdev/DMARC-SPF-Checker): Analyzing DMARC and SPF records for a list of domains.
* [`MX Toolbox`](https://mxtoolbox.com/): Listing MX records for a domain.

#### Identity Security
<ins>Description:</ins> Verifying user identities, detecting credential abuse and account takeover attempts, and actively responding to identity-based threats.

<ins>Tags:</ins>

* [`Push Security`](https://pushsecurity.com): Browser-based ITDR platform protecting against phishing, AitM, credential abuse, and account takeover.
* [`Teleport`](https://github.com/gravitational/teleport): Identity-aware access proxy providing secure connectivity, authentication (certificates, SSO, MFA), authorization (RBAC), and audit for infrastructure (SSH, K8s, DBs, RDP, web apps).

### Digital Forensics & Incident Response (DFIR)
<ins>Description:</ins> Hands-on analysis of security incidents by investigating and correlating evidence from disk, memory, and network artifacts.

<ins>Tags:</ins>

* [`Arsenal Image Mounter`](https://arsenalrecon.com/products/arsenal-image-mounter): Mounts forensic disk images as real disks in Windows, allowing for in-depth analysis with other tools.
* [`Autopsy`](https://www.autopsy.com/): An open-source digital forensics platform for analyzing disk images and mobile devices.
* [`Ciphey`](https://github.com/bee-san/Ciphey): Automated decryption/decoding tool using AI for cipher detection.
* [`CyberChef`](https://github.com/gchq/CyberChef): A web app for data encoding, decoding, encryption, hashing, formatting, and analysis.
* [`DC3DD/DD`](https://sourceforge.net/projects/dc3dd/): Command-line tools for creating bit-for-bit forensic images of storage media.
* [`EnCase`](https://www.guidance.com/encase-forensic): A commercial, court-accepted digital forensics platform for deep analysis of computer evidence.
* [`Eric Zimmerman's Tools`](https://ericzimmerman.github.io/#!index.md): A suite of essential command-line tools for parsing Windows forensic artifacts (e.g., MFT, Prefetch, Shellbags).
* [`FTK Imager`](https://www.exterro.com/digital-forensics-software/ftk-imager): A free data preview and imaging tool for creating forensic images and capturing live memory.
* [`KAPE (Kroll Artifact Parser and Extractor)`](https://www.kroll.com/en/services/cyber/incident-response-recovery/kroll-artifact-parser-and-extractor-kape): A forensic artifact collector and parser for quickly triaging a system to find evidence.
* [`Plaso (log2timeline)`](https://github.com/log2timeline/plaso): Python-based forensic engine for creating detailed timelines from diverse system artifacts.
* [`Velociraptor`](https://github.com/Velocidex/velociraptor): An advanced open-source tool for endpoint monitoring, digital forensics, and incident response at scale.
* [`Volatility Framework`](https://github.com/volatilityfoundation/volatility3): The industry-standard open-source framework for memory forensics and analyzing RAM dumps.
* [`Wireshark`](https://www.wireshark.org/): Network protocol analyzer for deep packet inspection and offline analysis of PCAPs.

#### Threat Intelligence & Detection
<ins>Description:</ins> Gathering, analyzing, and operationalizing threat data to proactively hunt for adversaries and detect malicious activity.

<ins>Tags:</ins>

* [`Cortex`](https://github.com/TheHive-Project/Cortex): Observable analysis and active response engine with numerous analyzers and responders.
* [`Cowrie`](https://github.com/cowrie/cowrie): SSH and Telnet honeypot designed to log brute force attacks and shell interaction.
* [`Dionaea`](https://github.com/DinoTools/dionaea): Low-interaction honeypot designed to trap malware by emulating vulnerable network services.
* [`IntelOwl`](https://github.com/intelowlproject/IntelOwl): Open-source platform for scaling threat intelligence operations by aggregating data from multiple sources.
* [`MalShare`](https://malshare.com/): Community malware repository with an API for sample submission and download.
* [`MalwareBazaar (abuse.ch)`](https://bazaar.abuse.ch/): Malware repository and threat intelligence platform for querying samples.
* [`MalwareSourceCode (vxunderground)`](https://github.com/vxunderground/MalwareSourceCode): A collection of malware source code for analysis and research.
* [`MISP`](https://github.com/MISP/MISP): Open-source threat intelligence platform for sharing, storing, and correlating IoCs.
* [`Shuffle`](https://github.com/Shuffle/Shuffle): Open-source Security Orchestration, Automation, and Response (SOAR) platform.
* [`SOC Prime`](https://tdm.socprime.com): Platform for collaborative cyber defense providing detection content (e.g., Sigma rules).
* [`ssdeep`](https://ssdeep-project.github.io/ssdeep/index.html): Computing and comparing fuzzy hashes (CTPH) to find similar malware.
* [`ThreatFox (abuse.ch)`](https://threatfox.abuse.ch/): Community-driven platform for sharing Indicators of Compromise (IOCs).
* [`Tines`](https://www.tines.com/): A commercial SOAR platform for automating security workflows.
* [`Tracecat`](https://github.com/TracecatHQ/tracecat): An open-source, case-centric SOAR platform.

### Others (Management, Purple Team)
#### Governance, Risk, and Compliance (GRC)
<ins>Description:</ins> Focuses on frameworks, processes, and tools for establishing security policies, managing cyber risk, and ensuring compliance with external and internal requirements.

<ins>Tags:</ins> User Training (M1017), Data Backup (M1053)

* [`Eramba`](https://github.com/eramba): Stable & feature-rich GRC platform.
* [`Comp AI`](https://github.com/trycompai/comp): New & under heavy-development GRC platform.
* [`Wizer`](https://www.wizer-training.com/): Security awareness training & phishing simulation.
* [`OpenCVE`](https://github.com/opencve/opencve): Open-source platform for aggregating, monitoring, and managing CVEs to support organizational risk management and compliance.

#### Cybersecurity Frameworks & Knowledge Bases
<ins>Description:</ins> Leveraging industry-standard frameworks and knowledge bases to understand threats, guide strategies, and enhance security posture.
* [`MITRE ATT&CK Mitigations`](https://attack.mitre.org/mitigations/enterprise/): Enterprise mitigation strategies mapped to ATT&CK techniques.
* [`MITRE ATT&CK Matrix`](https://attack.mitre.org/matrices/enterprise/): A framework of known adversary tactics and techniques.

#### Purple Team & Adversary Emulation
<ins>Description:</ins> Simulating attacker techniques to test, validate, and improve defensive controls and incident response capabilities.
* [`Atomic Red Team`](https://github.com/redcanaryco/atomic-red-team): A library of scripted tests mapped to MITRE ATT&CK for validating security visibility, detection coverage, and emulating adversary behaviors.
* [`AttackGen`](https://github.com/mrwadams/attackgen): LLM-powered tool using MITRE ATT&CK to generate tailored incident response scenarios for testing, training, and purple team exercises.