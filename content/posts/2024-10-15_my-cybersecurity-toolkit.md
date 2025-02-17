---
title: "My cybersecurity toolkit"
date: 2024-10-15T19:45:00+07:00
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

#### **Web Application Security Testing** 
Specifically focusing on vulnerabilities in web applications.
* [`gobuster`](https://github.com/OJ/gobuster): Directory and file brute-forcing tool.

#### **Network Security Testing** 
Evaluating the security of network infrastructure.
* [`Nmap`](https://nmap.org/): Powerful and versatile network scanner.

#### **Reconnaissance/Information Gathering**
* [`theHarvester`](https://github.com/laramies/theHarvester): Email and username gathering tool.
* [`hunter.io`](https://hunter.io/): Email address finding service.
* [`Enum4Linux`](https://github.com/CiscoCX/enum4linux): Tool for enumerating information from Windows and Samba systems.

#### **Exploit Development**
Creating and customizing payloads for penetration testing and exploit development.
* [`msfvenom`](https://www.metasploit.com/): Command-line payload generator for the Metasploit Framework.

#### **Password Cracking**
Attempting to recover passwords by trying various combinations of characters.
* [`Hydra`](https://github.com/vanhauser-thc/thc-hydra): Password cracking tool supporting various services.

#### **Physical Security Testing** 
Assessing the security of physical access controls and infrastructure.

#### **Red Teaming Exercises/Simulated Attacks** 
Conducting full-scale simulations to test an organization's defenses.  *(This is an activity, not a tool category itself.  Tools used here are drawn from the other Red Team categories.)*

#### **Post-Exploitation** 
Simulating actions an attacker might take after gaining access (e.g., data exfiltration, privilege escalation, persistence).

#### **Bypass Detection** 
Developing and testing techniques to evade security defenses.

## Blue Team (Defensive)

#### **Security Monitoring and Threat Detection** 
Continuously monitoring systems and networks for suspicious activity.
* [`Wazuh`](https://wazuh.com/): Open-source SIEM and EDR system.

#### **Incident Response** 
Responding to security incidents to contain them, mitigate damage, and restore systems.

#### **Vulnerability Management** 
Identifying and remediating vulnerabilities.
* [`Nessus (Tenable)`](https://www.tenable.com/products/nessus): Vulnerability scanner.

#### **Security Hardening** 
Implementing security controls to reduce the attack surface.

#### **Threat Intelligence** 
Gathering and analyzing information about potential threats.

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

#### **Intrusion Detection and Prevention**
Monitoring systems and networks for malicious activity and taking action to block or mitigate threats.
* [`CrowdSec`](https://crowdsec.net/):  Open-source collaborative intrusion detection and prevention system.

#### **Data Security** 
Protecting sensitive data.

#### **Identity and Access Management (IAM)** 
Managing user identities and access privileges.

#### **Endpoint Visibility**
Collecting and analyzing system data to detect suspicious activity, ensure compliance, and improve security posture. This includes tools for querying system state, logging events, and auditing configurations.
* [`osquery`](https://osquery.io/): Tool for querying system information using SQL.
* [`Sysmon`](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon): Windows system service that logs detailed system events.

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

## Other Security Functions

#### **DevSecOps (Development Security Operations)** 
Integrating security into the software development lifecycle (SDLC).

#### **GRC (Governance, Risk, and Compliance)** 
Managing security risk and ensuring compliance.
* [`Eramba`](https://github.com/eramba): Open-source GRC platform.  

#### **Security Engineering/Architecture** 
Designing, building, and maintaining secure systems. *(Similar to Blue Team's "Security Architecture and Design," but broader, encompassing both proactive and reactive aspects.)*

#### **Digital Forensics and Incident Response (DFIR)** 
Investigating security incidents and gathering evidence.

#### **Threat Intelligence Analysis** 
Collecting, analyzing, and disseminating threat information. *(Distinct from Blue Team's "Threat Intelligence" in that this is a specialized function, often performed by dedicated analysts.)*

#### **Security Operations Center (SOC) Operations** 
The day-to-day running of the SOC, including monitoring, incident response, and threat hunting. *(This is an *operational function* that uses tools from many categories.)*

#### **Vulnerability Research** 
Discovering new vulnerabilities.  *(This can support both Red and Blue teams.)*

#### **Security Management** 
Overseeing all aspects of an organization's security program. *(This is a *management* function, not a technical one.)*

#### **OSINT (Open Source Intelligence)**
Gathering and analyzing publicly available information to gain insights about targets, threats, or vulnerabilities.
* [`OSINT Framework`](https://osintframework.com/): A comprehensive collection of OSINT tools and techniques.  *(This is a resource, not a tool, but we include it here since it is a major OSINT resource)*
* [`Have I Been Pwned`](https://haveibeenpwned.com/): A website that allows users to check if their personal data has been compromised in data breaches.

#### **Malware Analysis**
Analyzing malware samples to understand their functionality, identify their characteristics, and develop detection methods.
* [`YARA`](https://virustotal.github.io/yara/):  Tool for identifying and classifying malware based on rules.
* [`sigtool`](https://virustotal.github.io/yara/): Utility for generating and managing YARA signatures.


## Windows System Utilities

* `sc.exe`: Service Control utility.  Used for managing Windows services (starting, stopping, configuring).
    * **Red Team Uses:** Creating or modifying services for persistence, privilege escalation, or lateral movement.  Disabling services to disrupt defenses.
    * **Blue Team Uses:**  Auditing service configurations, hardening service permissions, troubleshooting service-related issues, stopping malicious services during incident response.
* `reg`: Registry Editor. Used for viewing and modifying the Windows Registry.
    * **Red Team Uses:**  Modifying registry keys for persistence, information gathering, bypassing security controls, or executing payloads.
    * **Blue Team Uses:**  Auditing registry settings for security vulnerabilities, implementing security hardening configurations, investigating malware activity, analyzing system configurations.
* `ping`:  Basic network connectivity testing.  Checks if a host is reachable.
    * **Red Team Uses:**  Reconnaissance (checking if hosts are up), network mapping.
    * **Blue Team Uses:** Troubleshooting network connectivity issues, verifying network configurations.
* `traceroute`:  Traces the route packets take to reach a destination.  Helps identify network hops and potential bottlenecks.
    * **Red Team Uses:** Network mapping, identifying network infrastructure.
    * **Blue Team Uses:** Troubleshooting network latency issues, analyzing network paths.
* `dig`: Domain Information Groper.  Used for DNS lookups.  Retrieves DNS records for a domain.
    * **Red Team Uses:**  Reconnaissance (gathering information about a target's DNS records, identifying subdomains).
    * **Blue Team Uses:**  Troubleshooting DNS resolution issues, verifying DNS configurations.

## Sysinternals

This is a suite of powerful tools for managing, troubleshooting, and monitoring Windows systems.  Many are useful for both Red and Blue Teams.
* [`TCPView`](https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview):  A Windows program that displays detailed listings of all TCP and UDP endpoints on your system, including the process that owns each endpoint.
    * **Red Team Uses:** Identifying open ports and services, understanding network connections established by applications, finding potential attack vectors.
    * **Blue Team Uses:** Troubleshooting network connectivity issues, identifying malicious network connections, monitoring network activity, investigating malware communication.
* [`Process Explorer`](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer): Advanced process monitoring tool.  Displays information about running processes, including their parent processes, handles, and DLLs.
    * **Red Team Uses:** Analyzing running processes, identifying potential targets for attack, understanding process relationships, finding vulnerabilities in running applications.
    * **Blue Team Uses:** Troubleshooting performance issues, identifying malicious processes, investigating malware activity, analyzing system behavior.
