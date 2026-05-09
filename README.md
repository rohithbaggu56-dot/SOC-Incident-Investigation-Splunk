# SOC Incident Investigation – Brute Force & Password Spraying Analysis Using Splunk

## Overview

This project documents a full SOC-style incident investigation performed in a controlled home lab environment using Splunk Enterprise, Windows Event Logs, Azure NSG controls, and external threat intelligence validation.

The investigation focused on identifying and analyzing real-world brute-force and password spraying activity targeting an internet-exposed Windows Server VM.

Over multiple weeks, the lab collected authentic attack telemetry from external systems attempting unauthorized authentication against exposed RDP services.

## Disclaimer

This project was conducted in a controlled home lab environment for educational and defensive security purposes only.

---
## Lab Architecture

- Windows Server 2022 VM exposed to internet
- Splunk Enterprise used for log ingestion and analysis
- Windows Security Event Logs forwarded to Splunk
- Azure NSG rules used for containment
- VirusTotal used for threat intelligence enrichment


# Environment

| Component           | Technology                      |
| ------------------- | ------------------------------- |
| SIEM Platform       | Splunk Enterprise               |
| Operating System    | Windows Server 2022             |
| Cloud Platform      | Microsoft Azure                 |
| Log Source          | Windows Security Event Logs     |
| Threat Intelligence | VirusTotal                      |
| Investigation Focus | Brute Force / Password Spraying |
| Detection Events    | Event ID 4625 / 4624 / 4688     |

---

# Investigation Objectives

* Detect repeated failed authentication attempts
* Identify suspicious external source IPs
* Correlate failed and successful authentication events
* Validate malicious infrastructure using threat intelligence
* Investigate potential post-compromise activity
* Implement containment and remediation measures

---

## Detection Metrics

| Metric | Value |
|--------|-------|
| Failed Login Events | 17,126 |
| Unique External IPs | 27 |
| Successful Logins Investigated | 230 |
| Malicious IPs Validated | 2 |
| Event IDs Reviewed | 4624, 4625, 4688 |
| Investigation Period | ~21 Days |

# Attack Summary

* 17,126 failed login attempts analyzed
* 27 external source IP addresses identified
* Multiple brute-force and password spraying attempts detected
* Authentication activity investigated using Windows Security Event Logs
* Threat intelligence validation performed against suspicious IP addresses
* No evidence of post-compromise command execution identified

---

# MITRE ATT&CK Mapping

| Technique | Description                   |
| --------- | ----------------------------- |
| T1110     | Brute Force                   |
| T1110.003 | Password Spraying             |
| T1078     | Valid Accounts                |
| T1021.001 | Remote Desktop Protocol (RDP) |

---

# Investigation Workflow

## 1. Detection

Created Splunk alert logic to identify excessive failed authentication attempts and suspicious login behavior.

### SPL Query

```spl
index=main source="WinEventLog:Security" EventCode=4625
| stats count by Source_Network_Address
| sort - count
```

### Investigation Screenshot

<img width="1920" height="1080" alt="02-failed-login-source-ip-analysis" src="https://github.com/user-attachments/assets/f9796281-1a29-41a2-a413-aa002f63fe33" />

---

## 2. Password Spraying & Targeted Account Analysis

Analyzed failed authentication activity to identify targeted accounts and repeated password spraying behavior across multiple usernames.

### SPL Query

```spl
index=main source="WinEventLog:Security" EventCode=4625
| bucket _time span=5m
| stats count values(Account_Name) as Targeted_Accounts by _time Source_Network_Address
| where count > 10
| sort - count
```

### Investigation Screenshot

<img width="1920" height="1080" alt="01-password-spraying-targeted-accounts-analysis" src="https://github.com/user-attachments/assets/1ef0276c-d60d-4e20-8f7b-9c8b8e1ebe87" />

---

## 3. Successful Authentication Analysis

Investigated Windows Event ID 4624 logs to analyze successful authentication events, Windows Logon Types, and account behavior.

### SPL Query

```spl
index=main source="WinEventLog:Security" EventCode=4624
| stats count by Account_Name Logon_Type
| sort - count
```

### Investigation Screenshot

<img width="1920" height="1080" alt="03-successful-logon-account-and-logon-type-analysis" src="https://github.com/user-attachments/assets/4c33a2f9-f789-47f9-8b52-718e6fe55dac" />

---

## 4. Successful Login Correlation

Correlated successful authentication activity from a suspicious source IP to validate potential unauthorized access attempts.

### SPL Query

```spl
index=main source="WinEventLog:Security" EventCode=4624 Source_Network_Address=202.60.110.122
| stats count by Account_Name
```

### Investigation Screenshot

<img width="1920" height="1080" alt="06-successful-login-correlation-analysis" src="https://github.com/user-attachments/assets/c9967822-8a80-4e1f-b203-ee09ece4cd88" />

---

## 5. Threat Intelligence Validation

Validated suspicious source IP addresses using VirusTotal threat intelligence to improve triage confidence and enrich investigation context.

### VirusTotal Validation – IP 185.93.89.10

<img width="1920" height="1080" alt="04-virustotal-malicious-ip-validation-185 93 89 10" src="https://github.com/user-attachments/assets/925f61a7-929a-41a7-a610-91b791b03846" />

### VirusTotal Validation – IP 202.60.110.122

<img width="1920" height="1080" alt="05-virustotal-malicious-ip-validation-202 60 110 122" src="https://github.com/user-attachments/assets/d30fda35-d171-424d-b0d6-f1b87bf0f657" />

---

## 6. Post-Compromise Activity Investigation

Reviewed process creation events for indicators of follow-on activity such as command execution, PowerShell usage, or privilege escalation attempts.

### SPL Query

```spl
index=main source="WinEventLog:Security" EventCode=4688
(CommandLine="*cmd*" OR CommandLine="*powershell*" OR CommandLine="*net.exe*" OR CommandLine="*tasklist*")
| stats count by Account_Name, CommandLine, Computer
```

### Investigation Result

No suspicious post-compromise process execution activity identified.

### Investigation Screenshot

<img width="1920" height="1080" alt="07-post-compromise-process-execution-analysis" src="https://github.com/user-attachments/assets/3936a2c0-77b5-4246-80a2-1f8b048d093c" />

---

# Remediation Actions

* Enabled Windows Firewall protections
* Blocked suspicious IP addresses
* Restricted RDP exposure using Azure NSG rules
* Limited remote access to trusted IP addresses only
* Continued monitoring authentication activity through Splunk

---

# Key Findings

* Multiple external systems attempted unauthorized access against exposed RDP services
* Attackers targeted common usernames and service-related accounts
* Password spraying activity aligned with MITRE ATT&CK T1110.003
* SPL-based event correlation identified suspicious successful authentication activity
* Threat intelligence enrichment improved investigation confidence during triage
* No evidence of lateral movement or malicious process execution identified

---

# Skills Demonstrated

* SOC alert triage
* SPL query development
* Authentication log analysis
* Incident investigation workflows
* Threat intelligence validation
* Windows Event Log analysis
* MITRE ATT&CK mapping
* Azure network security controls
* Containment and remediation procedures

---

# Conclusion

This project provided hands-on experience with SOC investigation methodology using real-world authentication attack telemetry collected from an intentionally exposed lab environment.

The investigation workflow included detection, triage, log correlation, threat intelligence validation, containment, and post-compromise verification using Splunk Enterprise and Windows Security Event Logs.

The project helped strengthen practical understanding of:

* SIEM-based investigations
* Windows authentication analysis
* Brute-force and password spraying detection
* Threat intelligence enrichment
* Incident response workflows
* Security monitoring and remediation
