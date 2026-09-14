# Recon Agent Report — incident_5_v5

**Spearphishing Macro → Process Injection → LSASS Dump → WMI Lateral → DCSync Domain Compromise**

Multi-stage endpoint attack where a threat actor delivers a weaponized Office document
via spearphishing email. The embedded VBA macro spawns a child process that performs
process injection into svchost.exe for defense evasion, gaining SYSTEM context. The
injected code dumps LSASS memory to harvest cached domain admin credentials. The attacker
then uses WMI-based lateral movement to pivot to a secondary host and executes a DCSync
attack against the domain controller, achieving full domain-level compromise with access
to all credential hashes in Active Directory.

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

**Kill chain:** Initial Access → Execution → Defense Evasion → Credential Access → Lateral Movement → Credential Access

**Entry point:** Spearphishing email with weaponized Office document attachment

**Final objective:** DCSync replication to extract all Active Directory credential hashes


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1566.001` | Phishing: Spearphishing Attachment | A threat actor targets an employee (jsmith) at CONTOSO.LOCAL with a spearphishing email containing a weaponized Office document (.docm). The email is delivered through Exchange Online, generating an OfficeActivity log entry with Operation="MessageDelivered" and the attachment filename visible in SourceFileName. |
| 2 | Execution | `T1204.002` | User Execution: Malicious File | When the victim opens the document on workstation wkst01, the embedded VBA macro executes automatically. The macro spawns a child process (e.g., rundll32.exe or powershell.exe) which appears in DeviceProcessEvents with InitiatingProcessFileName="WINWORD.EXE". This child process serves as the staging ground for the next phase. |
| 3 | Defense Evasion | `T1055` | Process Injection | The spawned process performs process injection into a legitimate svchost.exe instance, leveraging techniques such as CreateRemoteThread or process hollowing. This is logged in DeviceProcessEvents showing the injection source process writing into svchost.exe's address space. The injected code now operates under NT AUTHORITY\SYSTEM context, evidenced by AccountSid changing to S-1-5-18 in subsequent process events. |
| 4 | Credential Access | `T1003.001` | OS Credential Dumping: LSASS Memory | Operating with SYSTEM privileges, the injected code accesses LSASS process memory to extract cached domain credentials. DeviceProcessEvents captures this as a process accessing lsass.exe, with ProcessCommandLine potentially showing credential dumping tools (mimikatz, procdump targeting lsass). The dump yields domain admin credentials (CONTOSO\DomainAdmin) cached from previous authentication sessions. |
| 5 | Lateral Movement | `T1047` | Windows Management Instrumentation | Using the harvested domain admin credentials, the attacker leverages the lateral-movement service to perform WMI-based remote execution on secondary workstation wkst02. The LateralMovementEvents table records this with LateralMovementType="WMI", SourceHost="wkst01", TargetHost="wkst02", and the domain admin AccountName. |
| 6 | Credential Access | `T1003.006` | OS Credential Dumping: DCSync | From the pivot host wkst02, the attacker executes a DCSync attack against domain controller dc01. This triggers Directory Service replication requests (EventID 4662 in WindowsSecurityEvents) from a non-domain-controller source IP. The DCSync operation uses the MS-DRSR protocol to request replication of password data, ultimately extracting all NTDS.dit credential hashes — including KRBTGT, enabling potential Golden Ticket attacks. The WindowsSecurityEvents log shows SubjectUserName as the compromised domain admin, with ObjectType referencing domainDNS and the DS-Replication-Get-Changes-All exte |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1017` | User Training | T1566.001 (Phishing: Spearphishing Attachment) | Train users to identify malicious attachments and report them quickly. |
| `M1021` | Restrict Web-Based Content | T1566.001 (Phishing: Spearphishing Attachment) | Block execution of mounted ISO contents and unsigned executables from email. |
| `M1031` | Network Intrusion Prevention | T1566.001 (Phishing: Spearphishing Attachment) | Detonate inbound attachments in a sandbox; block ISO / LNK / HTA where possible. |
