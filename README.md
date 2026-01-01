# Bridge Takeover – Incident Report  

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
<img width="684" height="109" alt="Flag 1 - Query" src="https://github.com/user-attachments/assets/467bb703-796a-4bdc-bd97-6e2479971616" />

#### Result:<img width="1123" height="200" alt="Flag 1 - Result" src="https://github.com/user-attachments/assets/7e71d1bc-5950-41db-85f9-1a3875da625c" />

### 🚩 Flag 2: Lateral Movement - Compromised Credentials

#### Query:<img width="684" height="109" alt="Flag 2 - Query" src="https://github.com/user-attachments/assets/5d00c615-6f7a-4cfb-b421-40f4244f97c9" />

#### Result:<img width="1123" height="200" alt="Flag 2 - Result" src="https://github.com/user-attachments/assets/de223718-534e-4427-9d4c-297418c406fb" />

### 🚩 Flag 3: Lateral Movement - Target Device

#### Query:<img width="681" height="106" alt="Flag 3 - Query" src="https://github.com/user-attachments/assets/9c10e6c8-a4d0-4649-ac6d-c23e197a2814" />

#### Result:<img width="1142" height="399" alt="Flag 3 - Result" src="https://github.com/user-attachments/assets/d0c9eb4e-5182-46ae-96a5-af09349f3b63" />

### 🚩 Flag 4: Execution - Payload Hosting Service

#### Query:<img width="698" height="284" alt="Flag 4 - Query" src="https://github.com/user-attachments/assets/d2365b50-70ee-4b7d-aa03-45db12801558" />

#### Result:<img width="779" height="167" alt="Flag 4 - Result" src="https://github.com/user-attachments/assets/20a35f3b-34e2-492d-bc87-c465ed9eedd8" />

### 🚩 Flag 5: Execution - Malware Download Command

#### Query:<img width="790" height="106" alt="Flag 5 - Query" src="https://github.com/user-attachments/assets/35d16c26-c138-4439-ab1e-09712079fe3c" />

#### Result:<img width="938" height="171" alt="Flag 5 - Result" src="https://github.com/user-attachments/assets/ae9a632e-32f2-4101-bbf8-dc8720377731" />

### 🚩 Flag 6: Execution - Archive Extraction Command

#### Query:<img width="515" height="108" alt="Flag 6 - Qeury" src="https://github.com/user-attachments/assets/2b26ca0e-e687-4185-9f8e-d60675d0f405" />

#### Result:<img width="865" height="114" alt="Flag 6 - Result" src="https://github.com/user-attachments/assets/6c52a7a5-df1d-4622-a438-8a9fc5f147be" />

### 🚩 Flag 7: Persistence - C2 Implant

#### Query: <img width="510" height="125" alt="Flag 7 - Query" src="https://github.com/user-attachments/assets/ef157a41-bec4-4b85-aa64-bade69557c8b" />

#### Result:<img width="664" height="115" alt="Flag 7 - Result" src="https://github.com/user-attachments/assets/59fbd6eb-8491-4991-b9d7-1116b1062dcc" />

### 🚩 Flag 8: Persistence - Named Pipe

#### Query:<img width="589" height="109" alt="Flag 8 - Query" src="https://github.com/user-attachments/assets/94cd02b7-ad46-4082-9d8e-88703e1efffb" />

#### Result:<img width="1040" height="312" alt="Flag 8 - Result" src="https://github.com/user-attachments/assets/9ef687bd-d7e2-44a5-902c-f8562f162d6d" />

### 🚩 Flag 9: Credential Access - Decoded Account Creation

#### Query:<img width="767" height="128" alt="Flag 9 - Query" src="https://github.com/user-attachments/assets/2b2eb05f-db2f-4c80-bc2c-619e27ab442f" />

#### Result:<img width="1418" height="185" alt="Flag 9 - Result" src="https://github.com/user-attachments/assets/978f1c4d-f312-4f3f-8b1a-9dcf825d069c" />

### 🚩 Flag 10: Persistence - Backdoor Account

#### Query:<img width="767" height="128" alt="Flag 10 - Query" src="https://github.com/user-attachments/assets/beff1d55-307a-404e-b52d-51bd8526ef38" />

#### Result:<img width="1418" height="185" alt="Flag 10 - Result" src="https://github.com/user-attachments/assets/8dd3b236-f89e-4cb0-bb03-7f506d7b5a8a" />

### 🚩 Flag 11: Persistence - Decoded Privilege Escalation Command

#### Query:<img width="767" height="128" alt="Flag 11 - Query" src="https://github.com/user-attachments/assets/61d9ae0e-9299-477c-9ee3-a378ee67aa13" />

#### Result:<img width="1418" height="185" alt="Flag 11 - Result" src="https://github.com/user-attachments/assets/3a9cf56f-034b-4fc7-80a5-d7e737acf4fe" />

### 🚩 Flag 12: Discovery - Session Enumeration

#### Query:<img width="684" height="125" alt="Flag 12 - Query" src="https://github.com/user-attachments/assets/c1e00402-51c7-4603-b81a-2fe40c526f22" />

#### Result:<img width="1739" height="452" alt="flag 12 - Result" src="https://github.com/user-attachments/assets/d7f4297e-c1ec-487d-af14-4d3d4909a5df" />

### 🚩 Flag 13: Discovery - Domain Trust Enumeration

#### Query:<img width="704" height="124" alt="Flag 13 - Query" src="https://github.com/user-attachments/assets/1d47d105-3de9-4365-b4d7-a089871c3a53" />

#### Result:<img width="818" height="171" alt="flag 13 - Result" src="https://github.com/user-attachments/assets/0b829a5b-5954-4540-a764-f2415e243a5e" />

### 🚩 Flag 14: Discovery - Network Connection Enumeration

#### Query:<img width="704" height="132" alt="Flag 14 - Query" src="https://github.com/user-attachments/assets/50868b96-3492-43b3-a631-c20fb30b6348" />

#### Result:<img width="780" height="169" alt="Flag 14 - Result" src="https://github.com/user-attachments/assets/a64257cc-69b6-4ac3-bc44-895a8278e42d" />

### 🚩 Flag 15: Discovery - Password Database Search

#### Query:<img width="664" height="103" alt="Flag 15 - Query" src="https://github.com/user-attachments/assets/e4458eed-cd82-45eb-b4e4-4f31ba2b0416" />

#### Result:<img width="1065" height="171" alt="Flag 15 - Result" src="https://github.com/user-attachments/assets/2728b431-f69c-46e2-9a65-6ec6d0fd01ec" />

### 🚩 Flag 16: Discovery - Credential File

#### Query:<img width="578" height="119" alt="Flag 16 - Query" src="https://github.com/user-attachments/assets/1b7ce32c-4431-4dbe-b2c9-499ea7c3aba1" />

#### Result:<img width="922" height="169" alt="Flag 16 - Result" src="https://github.com/user-attachments/assets/f0d66bd5-ca32-498a-ac58-c8e3bd3ebb5e" />

### 🚩 Flag 17: Collection - Data Staging Directory

#### Query:<img width="599" height="126" alt="Flag 17 - Query" src="https://github.com/user-attachments/assets/30c68984-8687-4fc2-8492-1680ce11fb08" />

#### Result:<img width="1457" height="227" alt="Flag 17 - Result" src="https://github.com/user-attachments/assets/da5328b6-3c25-4e1d-b864-67168b71587a" />

### 🚩 Flag 18: Collection - Automated Data Collection Command

#### Query:<img width="601" height="109" alt="Flag 18 - Query" src="https://github.com/user-attachments/assets/23ae99d9-e9b9-4675-8d3a-f882a6689511" />

#### Result:<img width="1008" height="143" alt="Flag 18 - Result" src="https://github.com/user-attachments/assets/9d60a8cb-f1fa-4ec5-99f3-81cb1cc44c92" />

### 🚩 Flag 19: Collection - Exfiltration Volume

#### Query:<img width="627" height="129" alt="Flag 19 - Query" src="https://github.com/user-attachments/assets/b582bdc2-95e7-45eb-8418-b72114444893" />

#### Result:<img width="929" height="259" alt="Flag 19 - Result" src="https://github.com/user-attachments/assets/71f1db53-2795-483f-a452-30623f483851" />

### 🚩 Flag 20: Credential Access - Credential Theft Tool Download

#### Query:<img width="479" height="124" alt="Flag 20 - Query" src="https://github.com/user-attachments/assets/e2ed6555-4a8c-447e-a854-f8aea2949f10" />

#### Result:<img width="691" height="113" alt="Flag 20 - Result" src="https://github.com/user-attachments/assets/8f5a49ea-88fc-47eb-b3e7-148d6ec35f23" />

### 🚩 Flag 21: Credential Access - Browser Credential Theft

#### Query:<img width="660" height="114" alt="Flag 21 - Query" src="https://github.com/user-attachments/assets/10e299ee-4b82-45dd-8c03-8c8dbca8652e" />

#### Result:<img width="1187" height="146" alt="Flag 21 - Result" src="https://github.com/user-attachments/assets/09fc080f-70df-4fd0-afb8-24c136e7a295" />

### 🚩 Flag 22: Exfiltration - Data Upload Command

#### Query:<img width="584" height="126" alt="Flag 22 - Query" src="https://github.com/user-attachments/assets/7d09936b-a61c-4119-95dc-09b92ab8acfc" />

#### Result:<img width="785" height="113" alt="flag 22 - Result" src="https://github.com/user-attachments/assets/1933a83e-144c-4bc5-8f00-8a1d71b63639" />

### 🚩 Flag 23: Exfiltration - Cloud Storage Service

#### Query:<img width="584" height="126" alt="Flag 23 - Query" src="https://github.com/user-attachments/assets/9b06e8cc-9825-4a53-860a-d66d930fe040" />

#### Result:<img width="785" height="113" alt="flag 23 - Result" src="https://github.com/user-attachments/assets/2d384955-c41e-422b-b2bc-54bdbc221873" />

### 🚩 Flag 24: Exfiltration - Destination Server

#### Query:<img width="592" height="108" alt="Flag 24 - Query" src="https://github.com/user-attachments/assets/bade74ac-7115-4a3e-98de-86681a483795" />

#### Result:<img width="914" height="141" alt="Flag 24 - Result" src="https://github.com/user-attachments/assets/0807fe90-ae37-4f10-ae8d-e68aa929ab9d" />

### 🚩 Flag 25: Credential Access - Master Password Extraction

#### Query:<img width="588" height="130" alt="Flag 25 - Query" src="https://github.com/user-attachments/assets/1e4016ec-a267-4da0-bd77-25799a74a27b" />

#### Result:<img width="861" height="144" alt="Flag 25 - Result" src="https://github.com/user-attachments/assets/b05b8c22-ece9-4d3e-b753-b1f1e1d86e10" />

---
