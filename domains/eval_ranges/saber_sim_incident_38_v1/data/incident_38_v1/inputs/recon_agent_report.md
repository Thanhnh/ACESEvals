# Recon Agent Report — incident_38_v1

**IIS Exploit → ASPX Web Shell → LSASS Dump → Domain Controller Lateral Movement**

A threat actor exploits a vulnerability in a public-facing IIS web application hosted on a
Windows Server to gain initial code execution. The attacker deploys an ASPX web shell for
persistent command-and-control access, enumerates domain accounts via LDAP queries, dumps
LSASS process memory to harvest cached domain administrator credentials, and pivots laterally
to the domain controller using SMB/PsExec with the stolen domain admin credentials. This
variant employs a direct credential-harvesting path on the compromised web server before
lateral movement to the DC.

_Generated: 2026-07-14T17:56:53+00:00_

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

**Kill chain:** Initial Access → Persistence → Discovery → Credential Access → Lateral Movement

**Entry point:** Exploitation of public-facing IIS web application vulnerability

**Final objective:** Gain domain controller access via lateral movement with domain admin credentials


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1190` | Exploit Public-Facing Application | Phase 1 — Initial Access (T1190): A threat actor identifies a public-facing IIS web application running on Windows Server "web-server-01" in the CONTOSO.LOCAL domain. The attacker exploits a remote code execution vulnerability in the application, causing the IIS worker process (w3wp.exe) to spawn an unauthorized child process (cmd.exe). This generates DeviceProcessEvents telemetry showing w3wp.exe as the parent of cmd.exe with suspicious command-line arguments. |
| 2 | Persistence | `T1505.003` | Server Software Component: Web Shell | Phase 2 — Persistence (T1505.003): Using the initial code execution, the attacker writes an ASPX web shell file (e.g., "error404.aspx") to the IIS webroot directory (C:\inetpub\wwwroot\). This provides persistent command execution capability through HTTP POST requests. DeviceFileEvents captures the file creation with w3wp.exe as the initiating process, and subsequent DeviceProcessEvents show w3wp.exe repeatedly spawning cmd.exe or powershell.exe as the web shell is used. |
| 3 | Discovery | `T1087.002` | Account Discovery: Domain Account | Phase 3 — Discovery (T1087.002): Through the web shell, the attacker executes domain enumeration commands ("net group 'Domain Admins' /domain", "nltest /dclist:CONTOSO", LDAP queries). These queries are logged on the domain controller dc-01 in WindowsSecurityEvents as LDAP search operations and SAM-R queries (Event IDs 4661, 4662). The attacker identifies domain administrator accounts and the domain controller hostname. |
| 4 | Credential Access | `T1003.001` | OS Credential Dumping: LSASS Memory | Phase 4 — Credential Access (T1003.001): The attacker uses the web shell to execute a credential dumping tool (e.g., procdump.exe targeting lsass.exe, or a Mimikatz variant) on web-server-01. Since the IIS application pool runs with elevated privileges or the attacker escalates via SeDebugPrivilege, LSASS process memory is successfully dumped. DeviceProcessEvents captures the LSASS access pattern — a suspicious process opening a handle to lsass.exe with PROCESS_VM_READ access. The attacker extracts cached NTLM hashes for the CONTOSO\DomainAdmin account. |
| 5 | Lateral Movement | `T1021.002` | Remote Services: SMB/Windows Admin Shares | Phase 5 — Lateral Movement (T1021.002): Armed with the domain administrator NTLM hash, the attacker performs pass-the-hash lateral movement from web-server-01 to dc-01 using SMB/PsExec (or similar remote execution tool). The lateral-movement service coordinates the cross-host operation. WindowsSecurityEvents on dc-01 records a Type 3 network logon (Event ID 4624) from web-server-01's IP address using the DomainAdmin account, followed by Event ID 4672 indicating special privileges assigned. LateralMovementEvents captures the PsExec method, source/target hosts, and credentials used. The attacker |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1016` | Vulnerability Scanning | T1190 (Exploit Public-Facing Application) | Continuously scan public surfaces and validate fixes. |
| `M1030` | Network Segmentation | T1190 (Exploit Public-Facing Application) | Isolate exposed workloads from sensitive backends; use private endpoints. |
| `M1050` | Exploit Protection | T1190 (Exploit Public-Facing Application) | Enable WAF / RASP and runtime protections for exposed application endpoints. |
| `M1051` | Update Software | T1190 (Exploit Public-Facing Application) | Patch internet-facing applications promptly; track CVEs against deployed versions. |
