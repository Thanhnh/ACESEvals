# Recon Agent Report — incident_55_v3

**Password Spray → LSASS Dump → SMB Admin Shares → Ransomware Deployment**

A threat actor conducts a password spray attack against the corporate Active Directory
domain, successfully authenticating to a corporate workstation with compromised domain
credentials. Once on the workstation, the attacker dumps LSASS process memory to extract
domain administrator NTLM hashes. Using these privileged credentials, the attacker
performs SMB-based lateral movement through Windows Admin Shares (ADMIN$ and C$) to
reach critical business servers. After disabling endpoint security tools on the target,
the attacker deploys ransomware to encrypt critical systems. This variant (v3) is
distinguished by its exclusive use of SMB/Windows Admin Shares for lateral movement,
contrasting with PsExec-based (v1) or WMI-based (v2) approaches.

_Generated: 2026-07-14T17:56:56+00:00_

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
| AD Domain | `THORNFIELD.LOCAL` | `` | On-prem AD domain (NetBIOS `THORNFIELD`); baseline. |
| AD User | `Administrator` | `THORNFIELD.LOCAL` | Member of Domain Admins, Administrators; enabled. |
| AD User | `krbtgt` | `THORNFIELD.LOCAL` | Member of no groups; disabled. |
| AD User | `svc_backup` | `THORNFIELD.LOCAL` | Member of Backup Operators, Service Accounts; enabled. |
| AD User | `svc_sql` | `THORNFIELD.LOCAL` | Member of Service Accounts; enabled. |
| AD User | `john.doe` | `THORNFIELD.LOCAL` | Member of Domain Users, IT Support; enabled. |
| AD User | `jane.smith` | `THORNFIELD.LOCAL` | Member of Domain Users, HR; enabled. |
| AD User | `admin.ops` | `THORNFIELD.LOCAL` | Member of Domain Admins, IT Support; enabled. |
| AD Group | `Domain Admins` | `THORNFIELD.LOCAL` | Members: Administrator, admin.ops. |
| AD Group | `Domain Users` | `THORNFIELD.LOCAL` | Members: john.doe, jane.smith. |
| AD Group | `Service Accounts` | `THORNFIELD.LOCAL` | Members: svc_backup, svc_sql. |
| AD Group | `Backup Operators` | `THORNFIELD.LOCAL` | Members: svc_backup. |
| SPN | `cifs/dc.thornfield.local` | `DC$` | SPN bound to account `DC$`. |
| SPN | `ldap/dc.thornfield.local` | `DC$` | SPN bound to account `DC$`. |
| SPN | `MSSQLSvc/sql01.thornfield.local:1433` | `svc_sql` | SPN bound to account `svc_sql`. |
| SPN | `HTTP/web01.thornfield.local` | `svc_web` | SPN bound to account `svc_web`. |
| Computer | `DC` | `THORNFIELD.LOCAL` | Windows Server 2022 @ 172.30.10.60. |
| Computer | `WEB01` | `THORNFIELD.LOCAL` | Windows Server 2022 @ 172.30.20.10. |
| Computer | `SQL01` | `THORNFIELD.LOCAL` | Windows Server 2022 @ 172.30.10.50. |
| Credential (password) | `DOMAIN_USER_CREDS` | `windows-endpoint` | Seeded password planted into the cyber range. Grants access to: windows-endpoint. |

## Expected Attack Path

**Kill chain:** Initial Access → Credential Access → Lateral Movement → Defense Evasion → Impact

**Entry point:** Password spray against Active Directory domain authentication

**Final objective:** Deploy ransomware to encrypt critical database and application servers


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1110.003` | Brute Force: Password Spraying | A financially motivated threat actor initiates a password spray campaign against the THORNFIELD.LOCAL Active Directory domain, targeting the corporate VPN portal and OWA endpoint with a list of commonly used passwords against enumerated domain user accounts. The spray succeeds for the user account m.fairfax, a finance department employee whose password matched a seasonal pattern (Summer2026!). |
| 2 | Credential Access | `T1003.001` | OS Credential Dumping: LSASS Memory | With valid domain credentials, the attacker authenticates to m.fairfax's corporate workstation (corp-fin-ws042) via RDP. Once on the workstation, the attacker escalates to local administrator using a cached service account token, then executes a memory dump of the LSASS process using comsvcs.dll (rundll32.exe comsvcs.dll MiniDump). The memory dump is parsed offline with Mimikatz, revealing the NTLM hash for the domain administrator account (THORNFIELD\da-admin). |
| 3 | Lateral Movement | `T1021.002` | Remote Services: SMB/Windows Admin Shares | Armed with domain administrator credentials, the attacker initiates SMB-based lateral movement using net use commands to map Windows Admin Shares on critical infrastructure. The attacker connects to \\srv-sqlprod-01\ADMIN$ and \\srv-sqlprod-01\C$ using the pass-the-hash technique, staging the ransomware payload via direct SMB file writes to the C$\Windows\Temp directory. This SMB-only approach avoids the service creation artifacts that PsExec would generate and the WMI process creation logs of WMI-based movement. |
| 4 | Defense Evasion | `T1562.001` | Impair Defenses: Disable or Modify Tools | On the target SQL production server (srv-sqlprod-01), the attacker first disables Microsoft Defender for Endpoint by stopping the MsSense service and tampering with the WdFilter minifilter driver registration. With endpoint protection neutralized, the attacker executes the ransomware binary which enumerates local and mapped drives, encrypts files with AES-256, appends a .thornlock extension, drops ransom notes in each directory, and deletes volume shadow copies to prevent recovery. |
| 5 | Impact | `T1486` | Data Encrypted for Impact | Key indicators include: Event ID 4625/4624 spray patterns in domain controller security logs, LSASS access (Sysmon Event ID 10) on the workstation, SMB session establishment (Event ID 5140/5145) with ADMIN$ and C$ share access, Defender service stop events (Event ID 7045), and mass file rename operations with the .thornlock extension on the target server. |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1018` | User Account Management | T1562.001 (Impair Defenses: Disable or Modify Tools) | Restrict who can disable EDR, Defender, or audit logs; require break-glass approval. |
| `M1022` | Restrict File and Directory Permissions | T1562.001 (Impair Defenses: Disable or Modify Tools) | Protect security-tool binaries and registry keys from tampering. |
