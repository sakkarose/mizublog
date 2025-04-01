---
title: "My cybersecurity toolkit"
date: 2023-12-30T19:45:00+07:00
lastmod: 2025-04-01T19:45:00+07:00
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

### Red Team (Offensive)

#### **Vulnerability Discovery**
Identifying weaknesses in systems, networks, and applications.

#### **Penetration Testing**
Simulating real-world attacks to exploit vulnerabilities and gain unauthorized access.

#### **Social Engineering** 
Manipulating individuals into divulging sensitive information or performing actions that compromise security.

#### **Wireless Security Testing** 
Assessing the security of wireless networks.

#### **Web Application Security** 
Specifically focusing on vulnerabilities in web applications.
* [`gobuster`](https://github.com/OJ/gobuster): Directory and file brute-forcing tool.

#### **Network Security Testing** 
Evaluating the security of network infrastructure.
* [`Nmap`](https://nmap.org/): Powerful and versatile network scanner.

#### **Reconnaissance/Information Gathering**
* [`theHarvester`](https://github.com/laramies/theHarvester): Email and username gathering tool.
* [`hunter.io`](https://hunter.io/): Email address finding service.
* [`Enum4Linux`](https://github.com/CiscoCX/enum4linux): Tool for enumerating information from Windows and Samba systems.

#### **Exploit**
Creating and customizing payloads for penetration testing and exploit development.
* [`msfvenom`](https://www.metasploit.com/): Command-line payload generator for the Metasploit Framework.
* [`PowerShell for Hackers`](https://github.com/I-Am-Jakoby/PowerShell-for-Hackers): Providing PowerShell payloads for various offensive purposes.

#### **Password Cracking**
Attempting to recover passwords by trying various combinations of characters.
* [`Hydra`](https://github.com/vanhauser-thc/thc-hydra): Password cracking tool supporting various services.

#### **Physical Security Testing** 
Assessing the security of physical access controls and infrastructure.

#### **Red Teaming Exercises/Simulated Attacks** 
Conducting full-scale simulations to test an organization's defenses.*

#### **Post-Exploitation** 
Simulating actions an attacker might take after gaining access (e.g., data exfiltration, privilege escalation, persistence).

#### **Bypass Detection** 
Developing and testing techniques to evade security defenses.

### Blue Team (Defensive)

#### **Security Monitoring and Threat Detection** 
Continuously monitoring systems and networks for suspicious activity.
* [`Wazuh`](https://wazuh.com/): Open-source SIEM and EDR system.
* [`Sysmon`](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon): Windows system service that logs detailed system events.

#### **Incident Response** 
Responding to security incidents to contain them, mitigate damage, and restore systems.
* [`Velociraptor`](https://github.com/Velocidex/velociraptor): Advanced endpoint monitoring, digital forensics, and incident response tool.

#### **Vulnerability Management** 
Identifying and remediating vulnerabilities.
* [`Nessus (Tenable)`](https://www.tenable.com/products/nessus): Vulnerability scanner.

#### **Security Hardening** 
Implementing security controls to reduce the attack surface.

#### **Threat Intelligence** 
Gathering and analyzing information about potential threats.
* [`Sophos Intelix`](https://intelix.sophos.com/): Threat intelligence platform for analyzing files and URLs.
* [`Ransomware-Tool-Matrix`](https://github.com/BushidoUK/Ransomware-Tool-Matrix):  A curated list of tools used by different ransomware and extortionist groups.
* [`maltrail`](https://github.com/stamparm/maltrail): A malicious traffic detection system that uses public and custom blacklists to identify threats.

#### **Security Awareness Training** 
Educating employees about security best practices.

#### **Log Management and Analysis** 
Collecting and analyzing security logs.

#### **Security Auditing** 
Assessing security controls and configurations.

#### **Endpoint Security** 
Protecting endpoint devices.
* [`ClamAV`](https://www.clamav.net/): Open-source antivirus engine.

#### **Network Security** 
Protecting network infrastructure.
* [`maltrail`](https://github.com/stamparm/maltrail): A malicious traffic detection system that uses public and custom blacklists to identify threats.

#### **Intrusion Detection and Prevention**
Monitoring systems and networks for malicious activity and taking action to block or mitigate threats.
* [`CrowdSec`](https://crowdsec.net/):  Open-source collaborative intrusion detection and prevention system.

#### **Web Application Security**
Protecting web applications from various attacks and vulnerabilities.
* [`BunkerWeb`](https://github.com/bunkerity/bunkerweb): Open-source self-hosted & cloud web application firewall.
* [`SafeLine`](https://github.com/chaitin/SafeLine):  Open-source self-hosted web application firewall.

#### **Email Security**
Tools and resources related to securing email communication and preventing email-based attacks.
* [`DMARC-SPF-Checker`](https://github.com/fdzdev/DMARC-SPF-Checker):  A tool to check the DMARC and SPF records of a domain.
* [`MX Toolbox`](https://mxtoolbox.com/): Website providing diagnostic tools for email servers.

#### **Data Security** 
Protecting sensitive data.

#### **Identity and Access Management (IAM)** 
Managing user identities and access privileges.

#### **Endpoint Visibility**
Collecting and analyzing system data to detect suspicious activity, ensure compliance, and improve security posture. This includes tools for querying system state, logging events, and auditing configurations.
* [`osquery`](https://osquery.io/): Tool for querying system information using SQL.

#### **Privileged Access Management (PAM)**
Managing and controlling access to privileged accounts and sensitive systems.
* [`JumpServer`](https://github.com/jumpserver/jumpserver): Open-source bastion host/PAM system.

#### **Cloud Security Posture Management (CSPM)**
Assessing and improving the security posture of cloud environments.
* [`Push Security`](https://pushsecurity.com): Cloud security posture management tool.

#### **Security Architecture and Design** 
Designing and implementing secure systems.

#### **Policy and Compliance** 
Developing and enforcing security policies.

#### **Malware Analysis**
Analyzing malware samples to understand their functionality, identify their characteristics, and develop detection methods.
* [`YARA`](https://virustotal.github.io/yara/):  Tool for identifying and classifying malware based on rules.
* [`VirusTotal`](https://www.virustotal.com/): Website for analyzing files and URLs for malware.
* [`Sophos Intelix`](https://intelix.sophos.com/): Threat intelligence platform for analyzing files and URLs.

### Other Security Functions

#### **DevSecOps (Development Security Operations)** 
Integrating security into the software development lifecycle (SDLC).

#### **GRC (Governance, Risk, and Compliance)** 
Managing security risk and ensuring compliance.
* [`Eramba`](https://github.com/eramba): Open-source GRC platform.   

#### **Security Engineering/Architecture** 
Designing, building, and maintaining secure systems. *(Broader, encompassing both proactive and reactive aspects.)*

#### **Digital Forensics and Incident Response (DFIR)** 
Investigating security incidents and gathering evidence.
* [`Chainsaw`](https://github.com/WithSecureLabs/chainsaw):  Memory forensics tool for incident response and malware analysis.
* [`FTK Imager`](https://accessdata.com/products-services/forensic-toolkit-ftk-imager): Tool for creating forensic images of disks and other media.
* [`gkape`](https://ericzimmerman.github.io/KapeDocs/#!Pages\5.-gkape.md):  Open-source incident response and forensics tool for memory and disk analysis.
* [`WinPmem`](https://github.com/Velocidex/WinPmem): Library for accessing physical memory in Windows, used for memory analysis and forensics.
* [`Volatility 3`](https://github.com/volatilityfoundation/volatility3):  Open-source memory forensics framework for extracting and analyzing information from volatile memory (RAM).
* [`LiME`](https://github.com/504ensicsLabs/LiME):  Loadable Kernel Module (LKM) that captures the contents of volatile memory (RAM) for later analysis.

#### **Threat Intelligence Analysis** 
Collecting, analyzing, and disseminating threat information. *(Distinct from Blue Team's which is often performed by dedicated analysts.)*

#### **Security Operations Center (SOC) Operations** 
The day-to-day running of the SOC, including monitoring, incident response, and threat hunting.

#### **Vulnerability Research** 
Discovering new vulnerabilities.

#### **Security Management** 
Overseeing all aspects of an organization's security program. *(This is a *management* function, not a technical one.)*

#### **OSINT (Open Source Intelligence)**
Gathering and analyzing publicly available information to gain insights about targets, threats, or vulnerabilities.
* [`OSINT Framework`](https://osintframework.com/): A comprehensive collection of OSINT tools and techniques.
* [`Have I Been Pwned`](https://haveibeenpwned.com/): A website that allows users to check if their personal data has been compromised in data breaches.
* [`onion-lookup`](https://github.com/ail-project/onion-lookup): Software for checking the existence of Tor hidden services and retrieving their metadata. 
* [`DomainTools`](https://www.domaintools.com/): Website providing information about domain names and IP addresses.
* [`URLScan.io`](https://urlscan.io/): Website for scanning and analyzing URLs.

#### **Data Analysis & Manipulation Tools**
Versatile tools for manipulating and analyzing data in various security contexts.
* [`CyberChef`](https://gchq.github.io/CyberChef/): Web-based application for data manipulation and analysis.

### Windows System Utilities

* `sc.exe` - Service Control utility for managing Windows services
  * **Red Team Uses:** Creating or modifying services for persistence, privilege escalation, or lateral movement. Disabling services to disrupt defenses.
  * **Blue Team Uses:** Auditing service configurations, hardening service permissions, troubleshooting service-related issues, stopping malicious services during incident response.

* `reg` - Registry Editor for viewing and modifying the Windows Registry
  * **Red Team Uses:** Modifying registry keys for persistence, information gathering, bypassing security controls, or executing payloads.
  * **Blue Team Uses:** Auditing registry settings for security vulnerabilities, implementing security hardening configurations, investigating malware activity, analyzing system configurations.

* `ping` - Basic network connectivity testing
  * **Red Team Uses:** Reconnaissance (checking if hosts are up), network mapping.
  * **Blue Team Uses:** Troubleshooting network connectivity issues, verifying network configurations.

* `traceroute` - Traces the route packets take to reach a destination
  * **Red Team Uses:** Network mapping, identifying network infrastructure.
  * **Blue Team Uses:** Troubleshooting network latency issues, analyzing network paths.

* `dig` - Domain Information Groper for DNS lookups
  * **Red Team Uses:** Reconnaissance (gathering information about a target's DNS records, identifying subdomains).
  * **Blue Team Uses:** Troubleshooting DNS resolution issues, verifying DNS configurations.

### Sysinternals

A suite of powerful tools for managing, troubleshooting, and monitoring Windows systems.

* [`TCPView`](https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview) - Displays detailed listings of TCP and UDP endpoints
  * **Red Team Uses:** Identifying open ports and services, understanding network connections established by applications, finding potential attack vectors.
  * **Blue Team Uses:** Troubleshooting network connectivity issues, identifying malicious network connections, monitoring network activity, investigating malware communication.

* [`Process Explorer`](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer) - Advanced process monitoring tool
  * **Red Team Uses:** Analyzing running processes, identifying potential targets for attack, understanding process relationships, finding vulnerabilities in running applications.
  * **Blue Team Uses:** Troubleshooting performance issues, identifying malicious processes, investigating malware activity, analyzing system behavior.
