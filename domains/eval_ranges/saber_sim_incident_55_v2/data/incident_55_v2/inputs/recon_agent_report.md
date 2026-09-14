# Recon Agent Report — incident_55_v2

**Valid Domain Accounts → LSASS Dump → SMB Lateral Movement → Disable Defender → Ransomware**

Multi-stage endpoint attack where a threat actor leverages compromised domain credentials
to gain initial access to a corporate workstation, dumps LSASS memory to obtain domain
administrator credentials, moves laterally via SMB admin shares to critical infrastructure
servers, disables endpoint security tools to evade detection, and deploys ransomware to
encrypt critical systems. This variant uses a direct SMB-based lateral movement path
distinct from previous variants.

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
| Credential (password) | `DOMAIN_USER_CREDS` | `domain-controller, windows-endpoint` | Seeded password planted into the cyber range. Grants access to: domain-controller, windows-endpoint. |

## Expected Attack Path

**Kill chain:** Initial Access → Credential Access → Lateral Movement → Defense Evasion → Impact

**Entry point:** Compromised domain user credentials used to authenticate to corporate workstation

**Final objective:** Deploy ransomware to encrypt critical infrastructure server file systems


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1078.002` | Valid Accounts: Domain Accounts | A threat actor possessing compromised domain credentials for user jsmith@CONTOSO.LOCAL authenticates to corporate workstation ws-endpoint-01 using valid domain account credentials (T1078.002). The attacker establishes an interactive session on the workstation. This initial logon generates DeviceProcessEvents showing the user session establishment and initial process creation (explorer.exe spawn). |
| 2 | Credential Access | `T1003.001` | OS Credential Dumping: LSASS Memory | Once on the workstation, the attacker executes a credential dumping tool targeting the LSASS process memory (T1003.001). Using rundll32.exe with comsvcs.dll MiniDump or a similar technique, the attacker extracts NTLM hashes for domain administrator account svc-admin cached in LSASS from a previous privileged logon session. This activity generates DeviceProcessEvents telemetry showing: the dumping process accessing lsass.exe with GrantedAccess 0x1FFFFF, the creation of the dump file, and the credential extraction tool execution chain. |
| 3 | Lateral Movement | `T1021.002` | Remote Services: SMB/Windows Admin Shares | Armed with domain administrator NTLM hash for svc-admin, the attacker initiates SMB lateral movement (T1021.002) directly to critical infrastructure server srv-critical-01 via administrative shares (\\srv-critical-01\C$ and \\srv-critical-01\ADMIN$). This variant specifically uses direct SMB-based lateral movement (net use, copy, and remote service creation) rather than PsExec or WMI. The lateral-movement service logs LateralMovementEvents capturing: source host (ws-endpoint-01), target host (srv-critical-01), movement type (smb), the domain admin credential used, and the commands staged on th |
| 4 | Defense Evasion | `T1562.001` | Impair Defenses: Disable or Modify Tools | Upon establishing SYSTEM-level access on the critical server, the attacker disables endpoint detection and response tools (T1562.001). Commands executed include: Set-MpPreference -DisableRealtimeMonitoring $true, sc config WinDefend start=disabled, and net stop WinDefend. These actions generate DeviceProcessEvents entries showing powershell.exe and sc.exe process executions with command-line arguments that disable security services. The MDE sensor detects the tampering and emits corresponding events. |
| 5 | Impact | `T1486` | Data Encrypted for Impact | Finally, the attacker deploys ransomware on the critical infrastructure server (T1486). The ransomware execution chain generates: DeviceProcessEvents showing vssadmin.exe delete shadows /all /quiet (VSS deletion), bcdedit /set {default} recoveryenabled No (disable recovery), and the ransomware binary execution. DeviceFileEvents captures the mass file rename operations (adding .locked extension to files) and ransom note creation (README_DECRYPT.txt) in each directory. The attack achieves its objective of rendering critical business data inaccessible through encryption. |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1018` | User Account Management | T1078.002 (Valid Accounts: Domain Accounts), T1562.001 (Impair Defenses: Disable or Modify Tools) | Apply least privilege; periodically review role assignments and remove unused accounts. |
| `M1022` | Restrict File and Directory Permissions | T1562.001 (Impair Defenses: Disable or Modify Tools) | Protect security-tool binaries and registry keys from tampering. |
| `M1027` | Password Policies | T1078.002 (Valid Accounts: Domain Accounts) | Enforce strong, rotated credentials and disable inactive / stale accounts. |
| `M1032` | Multi-factor Authentication | T1078.002 (Valid Accounts: Domain Accounts) | Require MFA on all human and service identities, especially for privileged roles and OAuth grants. |
