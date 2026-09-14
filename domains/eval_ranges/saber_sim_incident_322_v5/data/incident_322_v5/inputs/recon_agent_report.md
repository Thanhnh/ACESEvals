# Recon Agent Report — incident_322_v5

**SQL Injection → LDAP Domain Recon → WMI Lateral Movement → DNS Tunneling C2**

Variant 5 of the external exploitation to C2 scenario. A threat actor exploits a SQL
injection vulnerability in a public-facing web application behind Azure Front Door to gain
initial command execution on the backend Windows server. Unlike previous variants that
harvested cached credentials, this attacker performs active LDAP reconnaissance against the
domain controller to enumerate privileged accounts, then authenticates as a discovered
domain administrator. Lateral movement uses WMI remote process execution (distinct from
the RDP/SMB paths used in earlier variants) to reach a high-value workstation in the
engineering subnet. The attacker establishes persistence via a scheduled task disguised as
a system update process, which initiates a DNS tunneling C2 channel encoding commands
within DNS TXT queries — a protocol-level evasion technique that differs from the HTTPS
beaconing observed in previous variants. Evidence is observable in SecurityEvent (Windows
logon, process creation, and task registration events), CommonSecurityLog (anomalous DNS
query patterns at the network perimeter), and SecurityAlert (correlated detection of
suspicious WMI execution and DNS tunneling indicators).

_Generated: 2026-07-14T17:57:00+00:00_

## Entity Inventory

| Resource Type | Name | Parent Resource | Description |
|---|---|---|---|
| Subscription | `SABER-Sim Subscription` | `` | Subscription `12345678-1234-1234-1234-123456789abc` in tenant `87654321-4321-4321-4321-cba987654321`; baseline. |
| Tenant | `87654321-4321-4321-4321-cba987654321` | `SABER-Sim Subscription` | Azure AD tenant; baseline. |
| Resource Group | `production-rg` | `SABER-Sim Subscription` | Resource group in `eastus`; baseline. |
| Resource Group | `development-rg` | `SABER-Sim Subscription` | Resource group in `eastus`; baseline. |
| Managed Identity | `webapp-identity` | `production-rg` | SystemAssigned managed identity; baseline. |
| Managed Identity | `function-identity` | `production-rg` | SystemAssigned managed identity; baseline. |
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
| AD Domain | `ENGCORP.LOCAL` | `` | On-prem AD domain (NetBIOS `ENGCORP`); baseline. |
| AD User | `Administrator` | `ENGCORP.LOCAL` | Member of Domain Admins, Administrators; enabled. |
| AD User | `krbtgt` | `ENGCORP.LOCAL` | Member of no groups; disabled. |
| AD User | `svc_backup` | `ENGCORP.LOCAL` | Member of Backup Operators, Service Accounts; enabled. |
| AD User | `svc_sql` | `ENGCORP.LOCAL` | Member of Service Accounts; enabled. |
| AD User | `john.doe` | `ENGCORP.LOCAL` | Member of Domain Users, IT Support; enabled. |
| AD User | `jane.smith` | `ENGCORP.LOCAL` | Member of Domain Users, HR; enabled. |
| AD User | `admin.ops` | `ENGCORP.LOCAL` | Member of Domain Admins, IT Support; enabled. |
| AD Group | `Domain Admins` | `ENGCORP.LOCAL` | Members: Administrator, admin.ops. |
| AD Group | `Domain Users` | `ENGCORP.LOCAL` | Members: john.doe, jane.smith. |
| AD Group | `Service Accounts` | `ENGCORP.LOCAL` | Members: svc_backup, svc_sql. |
| AD Group | `Backup Operators` | `ENGCORP.LOCAL` | Members: svc_backup. |
| SPN | `cifs/dc.engcorp.local` | `DC$` | SPN bound to account `DC$`. |
| SPN | `ldap/dc.engcorp.local` | `DC$` | SPN bound to account `DC$`. |
| SPN | `MSSQLSvc/sql01.engcorp.local:1433` | `svc_sql` | SPN bound to account `svc_sql`. |
| SPN | `HTTP/web01.engcorp.local` | `svc_web` | SPN bound to account `svc_web`. |
| Computer | `DC` | `ENGCORP.LOCAL` | Windows Server 2022 @ 172.30.10.60. |
| Computer | `WEB01` | `ENGCORP.LOCAL` | Windows Server 2022 @ 172.30.20.10. |
| Computer | `SQL01` | `ENGCORP.LOCAL` | Windows Server 2022 @ 172.30.10.50. |
| Credential (password) | `DA_CREDENTIALS` | `domain-controller, lateral-movement, windows-endpoint` | Seeded password planted into the cyber range. Grants access to: domain-controller, lateral-movement, windows-endpoint. |
| Credential (scheduled_task) | `PERSISTENT_TASK` | `c2-server` | Seeded scheduled task planted into the cyber range. Grants access to: c2-server. |

## Expected Attack Path

**Kill chain:** Initial Access → Discovery → Privilege Escalation → Lateral Movement → Persistence → Command and Control

**Entry point:** SQL injection vulnerability in public-facing web application behind Azure Front Door

**Final objective:** Establish persistent DNS tunneling C2 channel on engineering workstation via scheduled task


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1190` | Exploit Public-Facing Application | A threat actor identifies a SQL injection vulnerability in a public-facing web application hosted on a Windows server (web-srv-01.engcorp.local) behind Azure Front Door. The application processes user input without parameterized queries, allowing injection of operating system commands via xp_cmdshell or similar SQL-to-OS execution paths. |
| 2 | Discovery | `T1087.002` | Account Discovery: Domain Account | Phase 1 — Initial Access (T1190): The attacker crafts a malicious HTTP request through Azure Front Door, exploiting the SQL injection flaw to achieve arbitrary command execution on the backend Windows server. SecurityEvent logs on web-srv-01 record anomalous child process creation (EventID 4688) with cmd.exe or powershell.exe spawning under the SQL Server process (sqlservr.exe) with ParentProcessName=sqlservr.exe. The Front Door WAF may log the suspicious request pattern but the injection payload evades signature-based detection. |
| 3 | Privilege Escalation | `T1078.002` | Valid Accounts: Domain Accounts | Phase 2 — Discovery (T1087.002): From the compromised web server, the attacker performs active LDAP reconnaissance against the domain controller (engcorp-dc01). Using net group "Domain Admins" /domain or direct LDAP queries (ldapsearch with filter (&(objectCategory=person)(adminCount=1))), the attacker enumerates all privileged domain accounts including membership in Domain Admins, Enterprise Admins, and Schema Admins groups. SecurityEvent on the domain controller records LDAP search operations (EventID 4662) indicating enumeration of sensitive AD objects. Unlike previous variants that harvest |
| 4 | Lateral Movement | `T1047` | Windows Management Instrumentation | Phase 3 — Privilege Escalation (T1078.002): Having identified the domain administrator account (administrator@ENGCORP.LOCAL), the attacker authenticates as this privileged user. The attacker discovers the DA password stored in an application configuration file accessible from the compromised SQL Server context (web.config connection string or stored procedure containing hardcoded credentials). SecurityEvent on engcorp-dc01 records a successful network logon (EventID 4624, LogonType=3) for the administrator account originating from web-srv-01's IP address, followed by special privilege assignme |
| 5 | Persistence | `T1053.005` | Scheduled Task/Job: Scheduled Task | Phase 4 — Lateral Movement (T1047): Armed with domain administrator credentials, the attacker uses Windows Management Instrumentation (WMI) to remotely execute a process on a high-value engineering workstation (eng-ws-04) in the engineering subnet. The WMI call (wmic /node:eng-ws-04 process call create) spawns a process under WmiPrvSE.exe on the target host. SecurityEvent on eng-ws-04 records: EventID 4624 (LogonType=3, TargetUserName=administrator, IpAddress=<web-srv-01-ip>) and EventID 4688 (process creation with ParentProcessName=WmiPrvSE.exe). SecurityAlert fires with AlertName="Suspicious |
| 6 | Command and Control | `T1071.004` | Application Layer Protocol: DNS | Phase 5 — Persistence (T1053.005): On the engineering workstation, the attacker creates a scheduled task named "WindowsSystemUpdate" disguised as a legitimate system update process. The task is configured to run at SYSTEM privilege level with a trigger every 5 minutes. SecurityEvent records the task creation (EventID 4698) with TaskName= \Microsoft\Windows\WindowsUpdate\WindowsSystemUpdate and TaskContent containing the encoded command payload. The task action launches a custom executable (svchost_update.exe) placed in C:\Windows\Temp\ that initiates the DNS tunneling channel upon each executi |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1016` | Vulnerability Scanning | T1190 (Exploit Public-Facing Application) | Continuously scan public surfaces and validate fixes. |
| `M1018` | User Account Management | T1078.002 (Valid Accounts: Domain Accounts) | Apply least privilege; periodically review role assignments and remove unused accounts. |
| `M1027` | Password Policies | T1078.002 (Valid Accounts: Domain Accounts) | Enforce strong, rotated credentials and disable inactive / stale accounts. |
| `M1030` | Network Segmentation | T1190 (Exploit Public-Facing Application) | Isolate exposed workloads from sensitive backends; use private endpoints. |
| `M1032` | Multi-factor Authentication | T1078.002 (Valid Accounts: Domain Accounts) | Require MFA on all human and service identities, especially for privileged roles and OAuth grants. |
| `M1050` | Exploit Protection | T1190 (Exploit Public-Facing Application) | Enable WAF / RASP and runtime protections for exposed application endpoints. |
| `M1051` | Update Software | T1190 (Exploit Public-Facing Application) | Patch internet-facing applications promptly; track CVEs against deployed versions. |
