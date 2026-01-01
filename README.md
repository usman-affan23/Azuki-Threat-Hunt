# Bridge Takeover – Incident Report  
## AZUKI File Server Compromise

**Cyber Security Incident Response Team (CSIRT)**  
**Incident Response Office**  
**Last Updated:** January 1st, 2026

---

## Report Metadata

| Field | Value |
|------|------|
| **Date of Report** | 2025-12-18 |
| **Severity Level** | CRITICAL |
| **Report Status** | CONTAINED |
| **Escalated To** | Cyber Security Incident Response Team (CSIRT) |
| **Incident ID** | INC-20251218-A7X |
| **Analyst** | Usman Affan |

---

## Purpose

This report documents the technical investigation and response actions associated with **Azuki Imports/Exports Trading Co., Ltd.** following the identification of malicious activity within the Azuki Virtual Environment.  
It provides a structured account of detection, analysis, containment, eradication, and recovery activities, aligned with standard incident response practices and NIST guidance.

---

## Incident Summary

Azuki Import/Export Trading Co. experienced a confirmed security incident involving unauthorized access to a privileged administrative workstation. Continuous monitoring and endpoint telemetry revealed anomalous Remote Desktop activity, execution of unauthorized tools, and obfuscated command execution consistent with post-compromise behavior.

Investigation determined that the threat actor leveraged previously compromised internal credentials to laterally move from an internal host to a high-value administrative system, establishing administrative-level access.

Following successful access, the attacker executed actions aligned with known adversary TTPs, including privilege escalation, persistence, discovery, credential access, and data exfiltration. Malicious activity included deployment of a command-and-control implant, creation of a covert local administrator account, enumeration of active user sessions, and extraction of stored credentials, including a password manager master password.

This incident posed a **critical risk** to confidentiality and integrity due to exposure of privileged credentials and demonstrated attacker persistence.

---

## WHO

### Attacker

- **Source IP:** `10.1.0.204`
- **C2 Infrastructure:**
  - `litter.catbox.moe` (malware staging)
  - Meterpreter C2 via named pipe:  
    `\Device\NamedPipe\msf-pipe-5902`

### Compromised

- **Accounts:**
  - `yuki.tanaka` (primary compromised credential)
  - `yuki.tanaka2` (malicious backdoor account)
- **System:** `azuki-adminpc`

---

## WHAT

### Credential Abuse and Lateral Movement
The attacker reused compromised credentials to authenticate via RDP from an internal host to a privileged administrative workstation.

### Malware Staging and Execution
A password-protected malicious archive was downloaded using a native command-line utility, extracted, and executed.

### Command and Control Establishment
A Meterpreter-based implant established persistent remote access using named pipe IPC.

### Persistence and Privilege Escalation
A covert local administrator account was created and elevated to ensure long-term access.

### Discovery and Session Enumeration
The attacker enumerated active RDP sessions, network connections, and domain trust relationships.

### Credential Access and Collection
Browser credentials, password databases, and a KeePass master password were extracted and staged locally.

---

## WHEN

**Incident Window:**  
`November 20, 2025 3:01:44 PM UTC → November 25, 2025 5:55:54 AM UTC`

- **Start:** November 20, 2025 – 3:01:44 PM UTC  
- **End:** November 25, 2025 – 5:55:54 AM UTC  
- **Exfiltration Window:**  
  `November 25, 2025 4:41:41 AM → 4:41:52 AM UTC`

---

## Verified Timeline

### Ordered by Time Generated (UTC)

| Flag | Time | Event |
|----|----|----|
| 1 | 4:06:52 AM | Lateral movement initiated from 10.1.0.204 |
| 2 | 4:06:52 AM | Compromised account `yuki.tanaka` reused |
| 12 | 4:08:58 AM | RDP session enumeration via `qwinsta` |
| 13 | 4:09:25 AM | Domain trust enumeration via `nltest` |
| 14 | 4:10:07 AM | Network connections enumerated via `netstat -ano` |
| 15 | 4:13:45 AM | KeePass databases searched |
| 5 | 4:21:11 AM | Malware downloaded via `curl.exe` |
| 6 | 4:21:32 AM | Archive extracted using `7z.exe` |
| 7 | 4:21:33 AM | Meterpreter C2 implant executed |
| 8 | 4:24:35 AM | Named pipe created |
| 17 | 4:37:03 AM | Data staged in Crypto directory |
| 19 | 4:37:33–4:40:30 AM | Eight archives prepared |
| 23 | 4:41:41 AM | Data uploaded to `gofile.io` |
| 22 | 4:41:51 AM | Data exfiltration via HTTP POST |
| 24 | 4:41:52 AM | Data transferred to `45.112.123.227` |
| 9 | 4:51:08 AM | Backdoor account created |
| 11 | 4:51:23 AM | Privilege escalation completed |
| 20 | 5:55:34 AM | Credential theft tool downloaded |
| 21 | 5:55:54 AM | Chrome credentials extracted |
| 25 | 3:01:44 PM | KeePass master password extracted |
| 16 | 3:01:52 PM | Plaintext password file discovered |

---

## WHERE

### Compromised System
- `azuki-adminpc`

### Infrastructure

**Attacker IPs**
- `10.1.0.204` (internal lateral movement source)
- `108.181.20.36` (external infrastructure)

**C2 Servers**
- `litter.catbox.moe`

### Malware Locations
- `C:\Windows\Temp\cache\KB5044273-x64.7z`
- `C:\Windows\Temp\cache\meterpreter.exe`
- `C:\ProgramData\Microsoft\Crypto\staging\`

---

## WHY

### Root Cause

- Insufficient protection of privileged credentials
- Lack of MFA and lateral movement controls on RDP
- Inadequate monitoring of living-off-the-land tools

### Attacker Objective

To establish persistent administrative access, harvest credentials, and exfiltrate sensitive business data for continued exploitation.

---

## HOW

1. Reused compromised credentials to regain access
2. Pivoted laterally to a privileged administrative workstation
3. Delivered malware via LOLBins (`curl.exe`, `7z.exe`)
4. Executed Meterpreter-based C2 implant
5. Established persistence via backdoor admin account
6. Perconfirm environment via discovery commands
7. Stole browser and password manager credentials
8. Staged and archived sensitive data
9. Exfiltrated data over HTTP web services

---

## IMPACT ASSESSMENT

### Actual Impact

- Exposure of sensitive business and financial data
- Compromise of privileged credentials and systems
- High likelihood of future unauthorized access

**Risk Level:** **CRITICAL**

---

## RECOMMENDATIONS

### IMMEDIATE

- Isolate compromised systems
- Disable backdoor accounts and reset credentials
- Block malicious infrastructure
- Remove C2 implants and persistence mechanisms

### SHORT-TERM (1–7 Days)

- Enterprise-wide credential resets
- Threat hunting for IOCs
- Harden RDP access and enforce MFA
- Preserve forensic artifacts

### LONG-TERM

- Implement Privileged Access Management (PAM)
- Improve LOLBin detection
- Strengthen network segmentation
- Conduct credential hygiene training

---

## APPENDIX

### A. Indicators of Compromise

| Category | Indicator | Description |
|------|------|------|
| Attacker IP | 10.1.0.204 | Internal lateral movement source |
| Attacker IP | 108.181.20.36 | External malicious infrastructure |
| C2 Server | litter.catbox.moe | Malware staging & exfiltration |
| File | KB5044273-x64.7z | Malicious archive |
| File | meterpreter.exe | C2 implant |
| Directory | Crypto\staging | Data staging path |
| Account | yuki.tanaka | Compromised user |
| Account | yuki.tanaka2 | Backdoor admin |

---

### B. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|------|------|------|
| Initial Access | Valid Accounts | T1078 |
| Execution | Command & Scripting Interpreter | T1059 |
| Persistence | Create Account | T1136.001 |
| Defense Evasion | Obfuscated Files | T1027 |
| Credential Access | Browser Credentials | T1555.003 |
| Lateral Movement | RDP | T1021.001 |
| Exfiltration | Web Services | T1567 |

---

### C. Evidence and Investigative Queries

*(Available upon request or in supporting investigation notebooks)*

---
