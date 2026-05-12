# SOC Incident Investigation – Brute Force & Password Spraying Analysis Using Splunk

## Overview

This project documents a full SOC-style incident investigation performed in a controlled home lab environment using Splunk Enterprise, Windows Security Event Logs, Azure NSG controls, and external threat intelligence validation.

The investigation focused on identifying and analyzing real-world brute-force and password spraying activity targeting an intentionally internet-exposed Windows Server VM.

Over multiple weeks, the lab collected authentic attack telemetry from external systems attempting unauthorized authentication against exposed RDP services.

#### NOTE:
This project was conducted in a controlled home lab environment for educational and defensive security purposes only.

---

## Lab Architecture

* Windows Server 2022 VM intentionally exposed to the internet within a controlled home lab environment
* Splunk Enterprise used for centralized log ingestion, monitoring, and analysis
* Windows Security Event Logs ingested into Splunk Enterprise
* Azure NSG rules used for containment and RDP access restriction
* VirusTotal used for external threat intelligence enrichment and IP validation



## 🗓️ Incident Timeline

| Date       | Event Description                                      |
|------------|--------------------------------------------------------|
| 2026-04-08 | Attack campaign begins from IP **185.93.89.10**        |
| 2026-04-28 | Breach detected – suspicious **ANONYMOUS_LOGON** from IP **202.60.110.122** |
| 2026-04-29 | Forwarder connectivity issues – log ingestion stopped  |
| 2026-05-07 | Historical authentication logs reviewed and investigation initiated in Splunk          |
| 2026-05-09 | Investigation completed – remediation verified         |


---

## Environment

| Component           | Technology                      |
| ------------------- | ------------------------------- |
| SIEM Platform       | Splunk Enterprise               |
| Operating System    | Windows Server 2022             |
| Cloud Platform      | Microsoft Azure                 |
| Log Source          | Windows Security Event Logs     |
| Threat Intelligence | VirusTotal                      |
| Investigation Focus | Brute Force / Password Spraying |
| Detection Events    | Event ID 4625 / 4624 / 4688     |


## Investigation Objectives

* Detect repeated failed authentication attempts
* Identify suspicious external source IPs
* Correlate failed and successful authentication events
* Validate malicious infrastructure using threat intelligence
* Investigate potential post-compromise activity
* Implement containment and remediation measures

---

## Detection Metrics

| Metric                         | Value            |
| ------------------------------ | ---------------- |
| Failed Login Events            | 17,126           |
| Unique External IPs            | 27               |
| Successful Logins Investigated | 230              |
| Malicious IPs Validated        | 2                |
| Event IDs Reviewed             | 4624, 4625, 4688 |
| Investigation Period           | ~21 Days         |


## Splunk Detection Dashboard

To improve visibility during investigation, a custom Splunk dashboard was created to visualize:

- Failed login activity trends
- Top attacking source IP addresses
- Targeted account distribution
- Total authentication failures

This dashboard helped support triage and investigation workflows by centralizing authentication telemetry and attack metrics.

<img width="1920" height="1080" alt="08-brute-force-detection-dashboard" src="https://github.com/user-attachments/assets/787f63ac-ba9b-4eeb-b440-cbe65eecefe3" />

---

## Attack Summary

* 17,126 failed login attempts analyzed
* 27 external source IP addresses identified
* Multiple brute-force and password spraying attempts detected
* Authentication activity investigated using Windows Security Event Logs
* Threat intelligence validation performed against suspicious IP addresses
* No evidence of post-compromise command execution identified

---

## MITRE ATT&CK Technique Mapping

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

<img width="1920" height="1080" alt="02-failed-login-source-ip-analysis" src="https://github.com/user-attachments/assets/f2fb6ee6-b689-457d-b61a-31d2df826406" />

---

## 2. Password Spraying & Targeted Account Analysis

Analyzed detailed authentication activity to identify targeted accounts and repeated password spraying behavior across multiple usernames.

### SPL Query

```spl
index=main source="WinEventLog:Security" EventCode=4625
| bucket _time span=5m
| stats count values(Account_Name) as Targeted_Accounts by _time Source_Network_Address
| where count > 10
| sort - count
```

### Investigation Screenshot

<img width="1920" height="1080" alt="01-password-spraying-targeted-accounts-analysis" src="https://github.com/user-attachments/assets/24c648bf-ebd6-4840-bc2d-7c431ee2a3cb" />

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

 <img width="1920" height="1080" alt="03-successful-logon-account-and-logon-type-analysis" src="https://github.com/user-attachments/assets/60ec39ff-58cc-4f06-a8ca-ef126c0f8d4d" />

---

## 4. Successful Login Correlation

Correlated successful authentication activity from a suspicious source IP to validate potential unauthorized access attempts.

### SPL Query

```spl
index=main source="WinEventLog:Security" EventCode=4624 Source_Network_Address=202.60.110.122
| stats count by Account_Name
```

### Investigation Screenshot

<img width="1920" height="1080" alt="06-successful-login-correlation-analysis" src="https://github.com/user-attachments/assets/e0350b62-3b15-4c3d-a0ea-e2beb7b86c7c" />

---

## 5. Threat Intelligence Validation

Validated suspicious source IP addresses using VirusTotal threat intelligence to improve triage confidence and enrich investigation context.

### VirusTotal Validation – IP 185.93.89.10

<img width="1920" height="1080" alt="04-virustotal-malicious-ip-validation-185 93 89 10" src="https://github.com/user-attachments/assets/736e159c-a344-4fda-9478-b8c725c8b618" />


### VirusTotal Validation – IP 202.60.110.122

<img width="1920" height="1080" alt="05-virustotal-malicious-ip-validation-202 60 110 122" src="https://github.com/user-attachments/assets/21a1bb16-2755-4f35-89a6-e2e1ba9d1b01" />

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

<img width="1920" height="1080" alt="07-post-compromise-process-execution-analysis" src="https://github.com/user-attachments/assets/a2ff55be-3b23-4649-a65b-23e79431812a" />

---

# Remediation Actions

* Enabled Windows Firewall protections
* Blocked suspicious IP addresses
* Restricted RDP exposure using Azure NSG rules
* Limited remote access to trusted IP addresses only
* Continued monitoring authentication activity through Splunk


## Detection & Prevention Improvements

**What Could Be Better:**

- **Real‑time alerting** → Trigger alerts on Event ID **4624** immediately after a spike in **4625** failures *(T1110 – Brute Force detected within minutes, not weeks)*  
- **Honeypot accounts** → Deploy decoy accounts to trigger instant response, preventing compromise of real accounts  
- **Threat intel automation** → Automate VirusTotal lookups for every failed login IP *(eliminate manual validation delays)*  
- **MFA on service accounts** → Enforce multi‑factor authentication to block breaches even if passwords are compromised  
- **Geo‑blocking** → Access restrictions for regions not expected to access exposed RDP services

---

# Key Findings

* Multiple external systems attempted unauthorized access against exposed RDP services
* Attackers targeted common usernames and service-related account names
* Password spraying activity aligned with MITRE ATT&CK T1110.003
* SPL-based event correlation identified suspicious successful authentication activity
* Threat intelligence enrichment improved investigation confidence during triage
* No evidence of lateral movement or malicious process execution identified



## Root Cause Analysis

The breach occurred because:

1. Windows Server exposed to the internet with security initially disabled (intentional for lab setup)
2. Exposed authentication services and weak access controls increased brute-force attack exposure
3. Delayed visibility caused by Splunk forwarder connectivity interruptions impacted real-time monitoring  
4. No MFA implemented on service accounts

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

This investigation simulated a real SOC analyst workflow from detection through containment and post-investigation validation.
