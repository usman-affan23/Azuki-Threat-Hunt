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

### Ordered by Flag Sequence

| Flag | Time Generated (UTC) | Event |
|------|----------------------|-------|
| 1 | 4:06:52 AM | The attacker initiates lateral movement from the previously compromised internal host at 10.1.0.204 to pivot deeper into the environment |
| 2 | 4:06:52 AM | The attacker reused the compromised legitimate account yuki.tanaka to authenticate during lateral movement, avoiding credential-based detection |
| 3 | 4:31:50 AM | The attacker targeted the high-value admin workstation azuki-adminpc, indicating intent to access privileged data and controls |
| 4 | 4:21:12 AM | The attacker leveraged the external file hosting service litter.catbox.moe to stage malicious payloads outside the organization |
| 5 | 4:21:11 AM | The attacker used curl.exe to download a malicious archive disguised as a Windows security update into a temporary cache directory |
| 6 | 4:21:32 AM | The attacker extracted a password-protected archive using 7z.exe, bypassing basic content inspection and application controls |
| 7 | 4:21:33 AM | The attacker deployed a Meterpreter-based command-and-control implant (meterpreter.exe) to maintain interactive remote access |
| 8 | 4:24:35 AM | The C2 implant created a named pipe (`\\Device\\NamedPipe\\msf-pipe-5902`) to enable stealthy local inter-process communication |
| 9 | 4:51:08 AM | The attacker executed an obfuscated PowerShell command to create a new local user account (yuki.tanaka2) for persistent access |
| 10 | 4:51:08 AM | The attacker established a covert backdoor account (yuki.tanaka2) to blend in with legitimate user naming conventions |
| 11 | 4:51:23 AM | The attacker escalated privileges by adding the backdoor account to the local Administrators group |
| 12 | 4:08:58 AM | The attacker enumerated active RDP sessions using `qwinsta` to identify logged-in users and potential targets |
| 13 | 4:09:25 AM | The attacker queried Active Directory trust relationships using `nltest /domain_trusts /all_trusts` to assess cross-domain movement paths |
| 14 | 4:10:07 AM | The attacker executed `netstat -ano` to identify active network connections and the processes owning them |
| 15 | 4:13:45 AM | The attacker recursively searched user directories for KeePass databases using `cmd.exe /c where /r C:\\Users *.kdbx` |
| 16 | 3:01:52 PM | The attacker discovered a plaintext credential file (`OLD-Passwords.txt`) reflecting poor password storage hygiene |
| 17 | 4:37:03 AM | The attacker staged collected data in `C:\\ProgramData\\Microsoft\\Crypto\\staging`, a path designed to appear authentic |
| 18 | 4:37:03 AM | The attacker used robocopy.exe with reliability flags to automate bulk theft of banking documents |
| 19 | 4:37:33 – 4:40:30 AM | The attacker prepared eight compressed archives, indicating significant data volume staged for exfiltration |
| 20 | 5:55:34 AM | The attacker downloaded a credential theft tool using curl.exe, reusing previously established infrastructure |
| 21 | 5:55:54 AM | The attacker extracted Chrome browser credentials using a DPAPI abuse module executed via m.exe |
| 22 | 4:41:51 AM | The attacker exfiltrated stolen data using a form-based HTTP POST upload via curl.exe |
| 23 | 4:41:41 AM | The attacker uploaded stolen data to the anonymous file-sharing service gofile.io to evade attribution |
| 24 | 4:41:52 AM | The attacker transferred data to the external server at 45.112.123.227, representing the final exfiltration endpoint |
| 25 | 3:01:44 PM | The attacker extracted and stored the KeePass master password in `KeePass-Master-Password.txt`, enabling full access to stored credentials |

### Ordered by Time Generated (UTC)

| Flag | Time Generated (UTC) | Event |
|------|----------------------|-------|
| 1 | 4:06:52 AM | The attacker initiates lateral movement from the previously compromised internal host at 10.1.0.204 to pivot deeper into the environment. |
| 2 | 4:06:52 AM | The attacker reused the compromised legitimate account yuki.tanaka to authenticate during lateral movement, avoiding credential-based detection. |
| 12 | 4:08:58 AM | The attacker enumerated active RDP sessions using `qwinsta` to identify logged-in users and potential targets. |
| 13 | 4:09:25 AM | The attacker queried Active Directory trust relationships using `nltest /domain_trusts /all_trusts` to assess cross-domain movement paths. |
| 14 | 4:10:07 AM | The attacker executed `netstat -ano` to identify active network connections and the processes owning them. |
| 15 | 4:13:45 AM | The attacker recursively searched user directories for KeePass databases using `cmd.exe /c where /r C:\Users *.kdbx`. |
| 5 | 4:21:11 AM | The attacker used curl.exe to download a malicious archive disguised as a Windows security update into a temporary cache directory. |
| 4 | 4:21:12 AM | The attacker leveraged the external file hosting service litter.catbox.moe to stage malicious payloads outside the organization. |
| 6 | 4:21:32 AM | The attacker extracted a password-protected archive using 7z.exe, bypassing basic content inspection and application controls. |
| 7 | 4:21:33 AM | The attacker deployed a Meterpreter-based command-and-control implant (meterpreter.exe) to maintain interactive remote access. |
| 8 | 4:24:35 AM | The C2 implant created a named pipe (`\Device\NamedPipe\msf-pipe-5902`) to enable stealthy local inter-process communication. |
| 3 | 4:31:50 AM | The attacker targeted the high-value administrative workstation azuki-adminpc, indicating intent to access privileged data and controls. |
| 17 | 4:37:03 AM | The attacker staged collected data in `C:\ProgramData\Microsoft\Crypto\staging`, a path designed to appear legitimate. |
| 18 | 4:37:03 AM | The attacker used robocopy.exe with reliability flags to automate bulk theft of banking documents. |
| 19 | 4:37:33 – 4:40:30 AM | The attacker prepared eight compressed archives, indicating significant data volume staged for exfiltration. |
| 23 | 4:41:41 AM | The attacker uploaded stolen data to the anonymous file-sharing service gofile.io to evade attribution. |
| 22 | 4:41:51 AM | The attacker exfiltrated stolen data using a form-based HTTP POST upload via curl.exe. |
| 24 | 4:41:52 AM | The attacker transferred data to the external server at 45.112.123.227, representing the final exfiltration endpoint. |
| 9 | 4:51:08 AM | The attacker executed an obfuscated PowerShell command to create a new local user account (yuki.tanaka2) for persistent access. |
| 10 | 4:51:08 AM | The attacker established a covert backdoor account (yuki.tanaka2) designed to blend in with legitimate naming conventions. |
| 11 | 4:51:23 AM | The attacker escalated privileges by adding the backdoor account to the local Administrators group. |
| 20 | 5:55:34 AM | The attacker downloaded a credential theft tool using curl.exe, reusing previously established infrastructure. |
| 21 | 5:55:54 AM | The attacker extracted Chrome browser credentials using a DPAPI abuse module executed via m.exe. |
| 25 | 3:01:44 PM | The attacker extracted and stored the KeePass master password in `KeePass-Master-Password.txt`, enabling full access to stored credentials. |
| 16 | 3:01:52 PM | The attacker discovered a plaintext credential file (`OLD-Passwords.txt`) reflecting poor password storage hygiene. |

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

### 🚩 Flag 1: Lateral Movement – Source System

#### Query: 

#### Result:

---
