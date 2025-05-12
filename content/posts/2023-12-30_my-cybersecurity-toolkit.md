---
title: "My cybersecurity toolkit"
date: 2023-12-30T19:45:00+07:00
lastmod: 2025-05-12T19:45:00+07:00
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
* [`theHarvester`](https://github.com/laramies/theHarvester): OSINT tool for gathering  names, emails, IPs, subdomains, and URLs by using multiple public resources.
* [`hunter.io`](https://hunter.io/): Email harvesting.
* [`CF-Hero`](https://github.com/musana/CF-Hero): With multiple methods, used to discover Cloudflare origin IPs.
* [`URLCrazy`](https://github.com/urbanadventurer/urlcrazy): OSINT tool to generate and test domain variations for typosquatting, phishing, or brand protection research.
* [`gobuster`](https://github.com/OJ/gobuster): Brute-force tool to discover URIs, DNS subdomains, Virtual Hosts, cloud buckets, and TFTP servers.
* [`Nmap`](https://nmap.org/): Initial network scanning of external targets to identify live hosts and broadly check for open ports/services.
* [`Sherlock`](https://github.com/sherlock-project/sherlock): OSINT tool to hunt down social media and other online accounts by username across numerous platforms.
* [`hcxdumptool`](https://github.com/ZerBea/hcxdumptool): Tool for capturing WiFi WPA/WPA2 handshakes and PMKIDs from wireless networks for subsequent cracking attempts.
* [`Osintgram`](https://github.com/amir-hosseinpour/Osintgram-fixed): OSINT tool for collecting, analyzing, and running reconnaissance on Instagram profiles.
* [`PhoneInfoga`](https://github.com/sundowndev/phoneinfoga): Advanced OSINT tool for scanning international phone numbers to gather associated information (carrier, line type, owner clues, social media presence, etc.).
* [`Pwnagotchi`](https://github.com/jayofelony/pwnagotchi): Raspberry Pi-based tool (using bettercap) for automatically capturing WPA/WPA2 handshakes and PMKIDs for offline cracking.
* [`Bjorn`](https://github.com/infinition/Bjorn): Pwnagotchi-like tool for network scanning, vulnerability assessment.
* [`Evil-M5Project`](https://github.com/7h30th3r0n3/Evil-M5Project): ESP32/M5Core2-based offensive toolkit for Wi-Fi attacks (Rogue AP, Evil Twin, deauth, Karma), network attacks, BadUSB, Bluetooth attacks, and C2, aimed at gaining access and control.
* [`Creepy`](https://github.com/ilektrojohn/creepy): OSINT tool that gathers and maps geolocation information from online sources (e.g., social media, photo metadata).
* [`GeoSpy`](https://github.com/atiilla/geospy): Python tool using an AI service (Graylark) to identify the geographical location where photos were taken.
* [`cloudscraper`](https://github.com/VeNoMouS/cloudscraper): Python module to bypass Cloudflare's anti-bot page (IUAM), enabling scraping and crawling of websites protected by these measures.

#### Initial Access (TA0001)
<ins>Description:</ins> Trying to get into victim's network.
* [`cuddlephish`](https://github.com/fkasler/cuddlephish): Browser-in-the-Middle (BitM) framework for phishing attacks to bypass MFA and capture sessions.
* [`Modlishka`](https://github.com/drk1wi/Modlishka): HTTP reverse proxy for advanced phishing attacks; facilitates 2FA bypass by capturing credentials and session cookies.
* [`Evilginx`](https://github.com/kgretzky/evilginx2): Man-in-the-middle attack framework for phishing credentials and session cookies to bypass 2FA.
* [`Muraena`](https://github.com/muraenateam/muraena): Reverse proxy for automating phishing and post-phishing activities, facilitating credential and session capture.
* [`EvilnoVNC`](https://github.com/JoelGMSec/EvilnoVNC): Phishing platform using a real browser over noVNC to bypass 2FA, capture credentials, sessions, and access browser profile data.
* [`Wifiphisher`](https://github.com/wifiphisher/wifiphisher): Rogue Access Point framework for Wi-Fi MitM attacks, phishing credentials (network keys, web logins), and malware deployment.
* [`CATSploit`](https://github.com/catsploit/catsploit): Automated penetration testing tool that gathers information, scores, and selects attack techniques, then executes them via Metasploit to compromise targets.
* [`Evil-M5Project`](https://github.com/7h30th3r0n3/Evil-M5Project): ESP32/M5Core2-based offensive toolkit for Wi-Fi attacks (Rogue AP, Evil Twin, deauth, Karma), network attacks, BadUSB, Bluetooth attacks, and C2, aimed at gaining access and control.

#### Credential Access (TA0006)
<ins>Description:</ins> Trying to steal account names and passwords.
* [`Ciphey`](https://github.com/bee-san/Ciphey): Automated decryption/decoding tool using AI for cipher detection; supports various encodings, classical ciphers, and some modern cryptography.
* [`Bjorn`](https://github.com/infinition/Bjorn): Pwnagotchi-like tool for brute-force attacks (FTP, SSH, SMB, etc.), and data exfiltration.
* [`cuddlephish`](https://github.com/fkasler/cuddlephish): Browser-in-the-Middle (BitM) framework for phishing attacks to bypass MFA and capture sessions.
* [`Modlishka`](https://github.com/drk1wi/Modlishka): HTTP reverse proxy for advanced phishing attacks; facilitates 2FA bypass by capturing credentials and session cookies.
* [`Evilginx`](https://github.com/kgretzky/evilginx2): Man-in-the-middle attack framework for phishing credentials and session cookies to bypass 2FA.
* [`Muraena`](https://github.com/muraenateam/muraena): Reverse proxy for automating phishing and post-phishing activities, facilitating credential and session capture.
* [`EvilnoVNC`](https://github.com/JoelGMSec/EvilnoVNC): Phishing platform using a real browser over noVNC to bypass 2FA, capture credentials, sessions, and access browser profile data.
* [`hashcat`](https://github.com/hashcat/hashcat): Advanced password recovery and cracking tool supporting numerous hash types and attack modes, capable of GPU acceleration.
* [`hcxtools`](https://github.com/ZerBea/hcxtools): Utilities to convert WiFi WPA/WPA2 packet captures (handshakes, PMKIDs) into hash formats for cracking with Hashcat or John the Ripper.
* [`Wifiphisher`](https://github.com/wifiphisher/wifiphisher): Rogue Access Point framework for Wi-Fi MitM attacks, phishing credentials (network keys, web logins), and malware deployment.
* [`wpa-sec.stanev.org`](https://wpa-sec.stanev.org/): Community-driven platform for distributed cracking of WPA/WPA2 PSKs from uploaded captures and Wi-Fi security research.
* [`Impacket`](https://github.com/fortra/impacket): Python toolkit with example scripts for network protocol interaction, widely used for attacking Windows/Active Directory environments (e.g., credential dumping via secretsdump.py, NTLM relaying, Kerberos manipulation).

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
* [`slowloris`](https://github.com/gkbrk/slowloris): HTTP Denial of Service tool that exhausts a web server's connection pool by slowly sending headers.

### Blue Team
#### Network Security
<ins>Description:</ins> Monitoring network traffic, controlling access, and actively preventing intrusions.

<ins>Tags:</ins> Network Intrusion Prevention (M1031), Filter Network Traffic (M1037), Network Segmentation (M1030)

* [`OPNsense`](https://opnsense.org/download/): FreeBSD-based, open-source, user-friendly firewall and routing platform.
* [`Snort`](https://www.snort.org/): Open-source Network Intrusion Prevention System (NIPS) and Intrusion Detection System (NIDS) that uses rule-based analysis of network traffic.
* [`testmynids.org`](https://github.com/3CORESec/testmynids.org): Website and script framework for testing Network Intrusion Detection System (NIDS) detection capabilities against known malicious patterns.
* [`Nzyme`](https://github.com/nzymedefense/nzyme): Wireless Intrusion Detection System (WIDS) and network monitor for detecting unauthorized devices (WiFi, Bluetooth, wired), rogue APs, and wireless attacks.

#### AppSec & DevSecOps
<ins>Description:</ins> Building security into applications, inspecting web traffic, and actively defending against exploits.

<ins>Tags:</ins> SSL/TLS Inspection (M1020), Exploit Protection (M1050)

* [`BunkerWeb`](https://github.com/bunkerity/bunkerweb): Nginx-based open-source Web Application Firewall (WAF).
* [`SafeLine`](https://github.com/chaitin/SafeLine): Open-source Web Application Firewall (WAF).
* [`grype`](https://github.com/anchore/grype): Vulnerability scanner for container images and filesystems, identifying known vulnerabilities in OS and language-specific packages.

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

#### Incident Response & Automation
<ins>Description:</ins> Analyzing security incidents, automating response workflows, and actively managing the containment, eradication, and recovery process.

<ins>Tags:</ins>

* [`Shuffle`](https://github.com/Shuffle/Shuffle): Open-source Security Orchestration, Automation, and Response (SOAR) platform.
* [`ssdeep`](https://ssdeep-project.github.io/ssdeep/index.html): Computing and comparing fuzzy hashes (CTPH) to find similar malware.
* [`MalShare`](https://malshare.com/): Community malware repository with an API for sample submission, download, and querying (SHA256, YARA hits, etc.).
* [`MalwareBazaar (abuse.ch)`](https://bazaar.abuse.ch/): Malware repository and threat intelligence platform with extensive API for querying samples/indicators and providing threat feeds.
* [`Wireshark`](https://www.wireshark.org/): Network protocol analyzer for deep packet inspection, live capture, and offline analysis (e.g., PCAPs). Includes `TShark` command-line utility often used in automation.
* [`Ciphey`](https://github.com/bee-san/Ciphey): Automated decryption/decoding tool using AI for cipher detection; supports various encodings, classical ciphers, and some modern cryptography.
* [`Cortex`](https://github.com/TheHive-Project/Cortex): Observable analysis and active response engine with numerous analyzers and responders, often integrated with TheHive SIRP.
* [`MalwareSourceCode (vxunderground)`](https://github.com/vxunderground/MalwareSourceCode): A collection of malware source code for in-depth analysis and research during incident response or malware studies.
* [`SOC Prime (Threat Detection Marketplace)`](https://tdm.socprime.com): Platform for collaborative cyber defense providing detection content (e.g., Sigma rules) for SIEMs, EDRs, and XDRs, supporting Detection as Code.
* [`MISP (Malware Information Sharing Platform)`](https://github.com/MISP/MISP): Open-source threat intelligence platform for sharing, storing, and correlating IoCs and threat information to support IR and security operations.
* [`Dionaea`](https://github.com/DinoTools/dionaea): Low-interaction honeypot designed to trap malware by emulating vulnerable network services and capturing exploit payloads.
* [`IntelOwl`](https://github.com/intelowlproject/IntelOwl): Open-source platform for scaling threat intelligence operations by aggregating and analyzing data on observables (files, IPs, domains, etc.) from multiple sources via API and GUI.
* [`RITA (Real Intelligence Threat Analytics)`](https://github.com/activecm/rita): Framework for detecting command and control (C2) communication (beaconing, DNS tunneling, etc.) through network traffic analysis of Zeek logs.
* [`CyberChef`](https://github.com/gchq/CyberChef): A web app for data encoding, decoding, encryption, hashing, formatting, and analysis.
* [`Plaso (log2timeline)`](https://github.com/log2timeline/plaso): Python-based forensic engine for extracting and correlating timestamped events from diverse system artifacts to create detailed timelines for incident response and analysis.

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
