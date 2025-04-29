---
title: "My cybersecurity toolkit"
date: 2023-12-30T19:45:00+07:00
lastmod: 2025-04-02T19:45:00+07:00
showLastmod: true
draft: true
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

https://ssdeep-project.github.io/ssdeep/index.html fuzzy hashing
https://tdm.socprime.com/ platform for  sharing detect rules
https://bazaar.abuse.ch/ https://malshare.com/ samples, malicious feeds, yara results resource
https://www.snort.org/ 
https://www.wireshark.org/docs/wsug_html_chunked/AppToolstshark.html


####   Exploitation

Developing and using exploits and payloads.

* [`msfvenom`](https://www.metasploit.com/): Metasploit payload generator.
* [`PowerShell for Hackers`](https://github.com/I-Am-Jakoby/PowerShell-for-Hackers): PowerShell payloads.
* [`Hydra`](https://github.com/vanhauser-thc/thc-hydra): Password cracker.

####   Network Stress Testing

Simulating attacks to assess network resilience and availability.

* [`MHDDoS`](https://github.com/MatrixTM/MHDDoS): DDoS attack tool.

##   Blue Team (Defensive)

####   Vulnerability Management

Identifying and remediating vulnerabilities.

* [`Nessus (Tenable)`](https://www.tenable.com/products/nessus): Vulnerability scanner.
* [`cvemap`](https://github.com/projectdiscovery/cvemap): CVE database CLI.
* [`Vulnhuntr`](https://github.com/protectai/vulnhuntr): LLM-powered vulnerability finder.
* [`APKDeepLens`](https://github.com/21hsmw/APKDeepLens): Android APK vulnerability scanner.
* [`OpenCVE`](https://github.com/opencve/opencve): Platform for managing and monitoring CVE data.

####   Threat Intelligence

Gathering and analyzing threat information.

* [`Sophos Intelix`](https://intelix.sophos.com/): Threat analysis platform.
* [`Ransomware-Tool-Matrix`](https://github.com/BushidoUK/Ransomware-Tool-Matrix): Ransomware tool TTPs.
* [`maltrail`](https://github.com/stamparm/maltrail): Malicious traffic detection.

####   Endpoint Security

Protecting endpoint devices.

* [`Sysmon`](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon): Windows event logger.
* [`osquery`](https://osquery.io/): System query tool.

####   Network Security

Protecting network infrastructure, monitoring for threats, and generating alerts.

* [`maltrail`](https://github.com/stamparm/maltrail): Malicious traffic detection.
* [`CrowdSec`](https://crowdsec.net/): Intrusion detection/prevention.
* [`Wazuh`](https://wazuh.com/): SIEM/EDR.
* [`NetAlertX`](https://github.com/jokob-sk/NetAlertX): Network/presence scanner & alerting.

####   Incident Response

Responding to security incidents.

* [`Velociraptor`](https://github.com/Velocidex/velociraptor): Endpoint forensics/IR.
* [`Chainsaw`](https://github.com/WithSecureLabs/chainsaw): Memory forensics.
* [`FTK Imager`](https://accessdata.com/products-services/forensic-toolkit-ftk-imager): Disk imaging.
* [`gkape`](https://ericzimmerman.github.io/KapeDocs/#!Pages\5.-gkape.md): Artifact parsing.
* [`WinPmem`](https://github.com/Velocidex/WinPmem): Memory acquisition.
* [`Volatility 3`](https://github.com/volatilityfoundation/volatility3): Memory analysis.
* [`LiME`](https://github.com/504ensicsLabs/LiME): Memory acquisition.

####   Privileged Access Management (PAM)

Managing privileged access.

* [`JumpServer`](https://github.com/jumpserver/jumpserver): Bastion host/PAM.


####   Malware Analysis

Analyzing malware.

* [`YARA`](https://virustotal.github.io/yara/): Malware rule engine.
* [`VirusTotal`](https://www.virustotal.com/): Malware analysis platform.
* [`Sophos Intelix`](https://intelix.sophos.com/): Threat analysis platform.
https://metadefender.com/ Threat analysis platform.
https://thedfirreport.com/ Malware analysis report

##   Other Security Functions

####   OSINT (Open Source Intelligence)

Gathering public information.

* [`OSINT Framework`](https://osintframework.com/): OSINT resources.
* [`Have I Been Pwned`](https://haveibeenpwned.com/): Breach data lookup.
* [`onion-lookup`](https://github.com/ail-project/onion-lookup): Tor hidden service lookup.
* [`DomainTools`](https://www.domaintools.com/): Domain information.
* [`URLScan.io`](https://urlscan.io/): URL analysis.
* [`CyberChef`](https://gchq.github.io/CyberChef/): Data manipulation.

##   Windows System Utilities

* `sc.exe` - Service Control utility
    * **Red Team Uses:** Service persistence/privesc.
    * **Blue Team Uses:** Service auditing/hardening.

* `reg` - Registry Editor
    * **Red Team Uses:** Registry persistence/info gathering.
    * **Blue Team Uses:** Registry auditing/hardening.

* `ping` - Network connectivity test
    * **Red Team Uses:** Host discovery.
    * **Blue Team Uses:** Network troubleshooting.

* `traceroute` - Network path tracer
    * **Red Team Uses:** Network mapping.
    * **Blue Team Uses:** Network troubleshooting.

* `dig` - DNS lookup tool
    * **Red Team Uses:** DNS reconnaissance.
    * **Blue Team Uses:** DNS troubleshooting.

##   Sysinternals

Windows system tools.

* [`TCPView`](https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview) - TCP/UDP endpoint viewer
    * **Red Team Uses:** Port/service identification.
    * **Blue Team Uses:** Network connection monitoring.

* [`Process Explorer`](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer) - Process information viewer
    * **Red Team Uses:** Process analysis.
    * **Blue Team Uses:** Malware detection.