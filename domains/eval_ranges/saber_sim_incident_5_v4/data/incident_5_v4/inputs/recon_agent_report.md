# Recon Agent Report — incident_5_v4

**Spearphishing Macro → Process Injection → LSASS Dump → WMI Lateral Movement → Ransomware**

Endpoint-focused multi-stage attack beginning with a spearphishing email delivering a
malicious Office document containing an embedded VBA macro. Upon execution, the payload
uses process injection (T1055) into svchost.exe to evade EDR detections. The injected
process dumps LSASS memory (T1003.001) to harvest domain administrator NTLM credentials.
Using the stolen domain admin hash, the attacker performs WMI-based lateral movement
(T1047) to a secondary workstation where ransomware is deployed (T1486), encrypting
critical files for maximum business impact. Variant 4 specifically employs WMI as the
lateral movement vector.

_Generated: 2026-07-15T19:11:40+00:00_

## Entity Inventory

| Resource Type | Name | Parent Resource | Description |
|---|---|---|---|
| Subscription | `SABER-Sim Subscription` | `` | Subscription `12345678-1234-1234-1234-123456789abc` in tenant `87654321-4321-4321-4321-cba987654321`; baseline. |
| Tenant | `87654321-4321-4321-4321-cba987654321` | `SABER-Sim Subscription` | Azure AD tenant; baseline. |
| Resource Group | `production-rg` | `SABER-Sim Subscription` | Resource group in `eastus`; baseline. |
| Resource Group | `development-rg` | `SABER-Sim Subscription` | Resource group in `eastus`; baseline. |
| Managed Identity | `webapp-identity` | `production-rg` | SystemAssigned managed identity; baseline. |
| Managed Identity | `function-identity` | `production-rg` | SystemAssigned managed identity; baseline. |
| Service Principal | `Exchange Mail Reader` | `Tenant` | Exchange-integration SP with permissions: Mail.Read, User.Read. |
| Service Principal | `app-insights-collector` | `Tenant` | Benign operational SP (monitoring / CI-CD / security / data baseline). |
| Service Principal | `prometheus-scraper` | `Tenant` | Benign operational SP (monitoring / CI-CD / security / data baseline). |
| Service Principal | `datadog-agent` | `Tenant` | Benign operational SP (monitoring / CI-CD / security / data baseline). |
| Service Principal | `log-analytics-shipper` | `Tenant` | Benign operational SP (monitoring / CI-CD / security / data baseline). |
| Service Principal | `github-actions-deploy` | `Tenant` | Benign operational SP (monitoring / CI-CD / security / data baseline). |
| Service Principal | `azure-devops-pipeline` | `Tenant` | Benign operational SP (monitoring / CI-CD / security / data baseline). |
| Service Principal | `terraform-automation` | `Tenant` | Benign operational SP (monitoring / CI-CD / security / data baseline). |
| Service Principal | `argocd-deployer` | `Tenant` | Benign operational SP (monitoring / CI-CD / security / data baseline). |
| Service Principal | `backup-agent` | `Tenant` | Benign operational SP (monitoring / CI-CD / security / data baseline). |
| Service Principal | `disaster-recovery-sync` | `Tenant` | Benign operational SP (monitoring / CI-CD / security / data baseline). |
| Service Principal | `defender-scanner` | `Tenant` | Benign operational SP (monitoring / CI-CD / security / data baseline). |
| Service Principal | `sentinel-connector` | `Tenant` | Benign operational SP (monitoring / CI-CD / security / data baseline). |
| Service Principal | `vault-sync` | `Tenant` | Benign operational SP (monitoring / CI-CD / security / data baseline). |
| Service Principal | `databricks-connector` | `Tenant` | Benign operational SP (monitoring / CI-CD / security / data baseline). |
| Service Principal | `synapse-worker` | `Tenant` | Benign operational SP (monitoring / CI-CD / security / data baseline). |
| Service Principal | `adf-pipeline` | `Tenant` | Benign operational SP (monitoring / CI-CD / security / data baseline). |
| Service Principal | `slack-notifications` | `Tenant` | Benign operational SP (monitoring / CI-CD / security / data baseline). |
| Service Principal | `pagerduty-webhook` | `Tenant` | Benign operational SP (monitoring / CI-CD / security / data baseline). |
| Service Principal | `jira-sync` | `Tenant` | Benign operational SP (monitoring / CI-CD / security / data baseline). |
| AD Domain | `CONTOSO.LOCAL` | `` | On-prem AD domain (NetBIOS `CONTOSO`); baseline. |
| AD User | `Administrator` | `CONTOSO.LOCAL` | Member of Domain Admins, Administrators; enabled. |
| AD User | `krbtgt` | `CONTOSO.LOCAL` | Member of no groups; disabled. |
| AD User | `svc_backup` | `CONTOSO.LOCAL` | Member of Backup Operators, Service Accounts; enabled. |
| AD User | `svc_sql` | `CONTOSO.LOCAL` | Member of Service Accounts; enabled. |
| AD User | `john.doe` | `CONTOSO.LOCAL` | Member of Domain Users, IT Support; enabled. |
| AD User | `jane.smith` | `CONTOSO.LOCAL` | Member of Domain Users, HR; enabled. |
| AD User | `admin.ops` | `CONTOSO.LOCAL` | Member of Domain Admins, IT Support; enabled. |
| AD Group | `Domain Admins` | `CONTOSO.LOCAL` | Members: Administrator, admin.ops. |
| AD Group | `Domain Users` | `CONTOSO.LOCAL` | Members: john.doe, jane.smith. |
| AD Group | `Service Accounts` | `CONTOSO.LOCAL` | Members: svc_backup, svc_sql. |
| AD Group | `Backup Operators` | `CONTOSO.LOCAL` | Members: svc_backup. |
| SPN | `cifs/dc.contoso.local` | `DC$` | SPN bound to account `DC$`. |
| SPN | `ldap/dc.contoso.local` | `DC$` | SPN bound to account `DC$`. |
| SPN | `MSSQLSvc/sql01.contoso.local:1433` | `svc_sql` | SPN bound to account `svc_sql`. |
| SPN | `HTTP/web01.contoso.local` | `svc_web` | SPN bound to account `svc_web`. |
| Computer | `DC` | `CONTOSO.LOCAL` | Windows Server 2022 @ 172.30.10.60. |
| Computer | `WEB01` | `CONTOSO.LOCAL` | Windows Server 2022 @ 172.30.20.10. |
| Computer | `SQL01` | `CONTOSO.LOCAL` | Windows Server 2022 @ 172.30.10.50. |

## Expected Attack Path

**Kill chain:** Initial Access → Defense Evasion → Credential Access → Lateral Movement → Impact

**Entry point:** Spearphishing email with malicious Office document containing VBA macro

**Final objective:** Ransomware deployment encrypting critical files on secondary workstation


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1566.001` | Phishing: Spearphishing Attachment | A threat actor sends a targeted spearphishing email to jsmith@contoso.local containing a malicious Word document disguised as a quarterly financial report. When jsmith opens the attachment, the embedded VBA macro executes, spawning a PowerShell child process from WINWORD.EXE. This initial payload downloads a second-stage shellcode loader. |
| 2 | Defense Evasion | `T1055` | Process Injection | The loader performs process injection (T1055) into a legitimate svchost.exe instance using process hollowing techniques. This evades endpoint detection by operating under a trusted Windows process context. The injected code running within svchost.exe then targets the Local Security Authority Subsystem Service (LSASS) process, reading its memory space to extract cached credential material (T1003.001). Among the harvested credentials is the NTLM hash for the CONTOSO\DomainAdmin account, which was cached from a recent administrative logon session. |
| 3 | Credential Access | `T1003.001` | OS Credential Dumping: LSASS Memory | Armed with the domain administrator hash, the attacker leverages Windows Management Instrumentation (WMI) for lateral movement (T1047). Using the command "wmic /node:workstation-2 /user:CONTOSO\DomainAdmin process call create", the attacker spawns a remote process on workstation-2 (used by analyst01). This WMI-based approach (Variant 4's distinguishing characteristic) generates logon type 3 events and WMI operational logs on the target. |
| 4 | Lateral Movement | `T1047` | Windows Management Instrumentation | On workstation-2, the remotely spawned process downloads and executes the ransomware payload (T1486). The ransomware enumerates local and mapped drives, encrypting files matching document, spreadsheet, database, and archive extensions with a .locked suffix. A ransom note (README_RESTORE.txt) is dropped in each affected directory. Volume Shadow Copies are deleted to prevent recovery. |
| 5 | Impact | `T1486` | Data Encrypted for Impact | Detection evidence spans multiple log sources: DeviceProcessEvents captures the full process execution chain (WINWORD → PowerShell → svchost injection → LSASS access); SecurityEvent captures Windows Security Events including the suspicious LSASS access (Event ID 4663), WMI remote logon (Event ID 4624 Type 3), and service creation; SecurityAlert captures the MDATP alerts triggered for credential dumping and ransomware behavior; Syslog captures network-level indicators of the WMI DCOM communication and anomalous SMB activity between hosts. |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1017` | User Training | T1566.001 (Phishing: Spearphishing Attachment) | Train users to identify malicious attachments and report them quickly. |
| `M1021` | Restrict Web-Based Content | T1566.001 (Phishing: Spearphishing Attachment) | Block execution of mounted ISO contents and unsigned executables from email. |
| `M1031` | Network Intrusion Prevention | T1566.001 (Phishing: Spearphishing Attachment) | Detonate inbound attachments in a sandbox; block ISO / LNK / HTA where possible. |
