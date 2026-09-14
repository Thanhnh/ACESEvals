# Recon Agent Report — incident_5_v1

**Spearphishing Attachment → Process Injection → LSASS Dump → Lateral Movement**

Endpoint-focused intrusion where a threat actor delivers a malicious document via
spearphishing email. Upon execution, the payload injects into a legitimate system
process to evade endpoint detection, then dumps LSASS memory to harvest domain
credentials. The attacker uses the stolen credentials to move laterally to a
secondary workstation via SMB/Windows Admin Shares.

_Generated: 2026-07-14T17:57:01+00:00_

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

**Kill chain:** Initial Access → Defense Evasion → Credential Access → Lateral Movement

**Entry point:** Spearphishing attachment delivered via email to victim workstation

**Final objective:** Lateral movement to secondary workstation using harvested domain credentials


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1566.001` | Phishing: Spearphishing Attachment | A threat actor crafts a weaponized Office document (.docm with embedded macro) and delivers it via spearphishing email targeting jsmith at CONTOSO.LOCAL. The email mimics a legitimate business communication and arrives at the victim's mailbox on wkst-victim. |
| 2 | Defense Evasion | `T1055` | Process Injection | Upon opening the attachment, the embedded macro executes a PowerShell stager that establishes an initial shell (INITIAL_SHELL) on the victim workstation. Evidence of this initial execution chain (WINWORD.EXE → powershell.exe) appears in DeviceProcessEvents and SecurityEvent logs. |
| 3 | Credential Access | `T1003.001` | OS Credential Dumping: LSASS Memory | The malware immediately performs process injection (T1055) into svchost.exe, a legitimate Windows system process, to evade endpoint detection and response tooling. This grants the attacker SYSTEM-level execution context (SYSTEM_ACCESS). The injection activity triggers SecurityAlert detections and is visible in DeviceProcessEvents as cross-process memory writes. |
| 4 | Lateral Movement | `T1021.002` | Remote Services: SMB/Windows Admin Shares | Operating from the injected process with elevated privileges, the attacker dumps LSASS process memory (T1003.001) using a reflective in-memory technique to avoid dropping tools to disk. The memory dump yields NTLM hashes and Kerberos tickets for domain accounts, including dadmin's privileged credentials (DOMAIN_CREDENTIALS). This activity is logged in DeviceProcessEvents (LSASS access) and generates SecurityAlert entries. |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1017` | User Training | T1566.001 (Phishing: Spearphishing Attachment) | Train users to identify malicious attachments and report them quickly. |
| `M1021` | Restrict Web-Based Content | T1566.001 (Phishing: Spearphishing Attachment) | Block execution of mounted ISO contents and unsigned executables from email. |
| `M1031` | Network Intrusion Prevention | T1566.001 (Phishing: Spearphishing Attachment) | Detonate inbound attachments in a sandbox; block ISO / LNK / HTA where possible. |
