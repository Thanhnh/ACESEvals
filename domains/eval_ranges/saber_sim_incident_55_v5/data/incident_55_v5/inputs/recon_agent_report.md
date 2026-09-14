# Recon Agent Report — incident_55_v5

**Valid Accounts → LSASS Dump → SMB Lateral Movement → Ransomware**

A threat actor leverages compromised valid domain credentials to authenticate to a
corporate workstation. Once on the endpoint, the attacker dumps LSASS process memory
to extract cached domain administrator NTLM hashes. Using these elevated credentials,
the attacker moves laterally via SMB/Windows Admin Shares to a critical file server.
On the target system, security tools are disabled to evade detection before deploying
ransomware that encrypts critical business data. Variant 5 differentiates from prior
variants by using SMB-based lateral movement and a credential-dump-first sequence
before pivoting to the target server.

_Generated: 2026-07-14T17:56:55+00:00_

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

**Kill chain:** Initial Access → Credential Access → Lateral Movement → Defense Evasion → Impact

**Entry point:** Compromised valid domain account logon to corporate workstation

**Final objective:** Deploy ransomware to encrypt critical data on target server


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1078` | Valid Accounts | A threat actor who has previously obtained valid domain credentials for user jsmith authenticates to a corporate workstation (corp-ws-055) on the CONTOSO.LOCAL domain using compromised credentials (T1078). The domain controller (contoso-dc) validates the authentication, generating WindowsSecurityEvents entries: Event ID 4624 (Logon Type 10 - RemoteInteractive) on the workstation and Event ID 4672 (Special Privilege Logon) recording the session establishment. The domain-controller /bind endpoint processes this authentication. |
| 2 | Credential Access | `T1003.001` | OS Credential Dumping: LSASS Memory | Once established on the workstation with a valid domain session, the attacker executes a credential dumping tool targeting the LSASS process memory (T1003.001) via the windows-endpoint /credential/dump-lsass endpoint. The workstation has cached domain administrator NTLM hashes from previous privileged logon sessions. This activity generates DeviceProcessEvents entries showing: suspicious process creation (procdump.exe -ma lsass.exe or rundll32.exe comsvcs.dll MiniDump), process access to lsass.exe with PROCESS_VM_READ rights, and credential material extraction. The attacker obtains the DOMAIN_ |
| 3 | Lateral Movement | `T1021.002` | Remote Services: SMB/Windows Admin Shares | Armed with the domain administrator NTLM hash, the attacker initiates lateral movement via SMB/Windows Admin Shares (T1021.002) to the critical file server srv-file-012. The lateral-movement service /smb/srv-file-012/copy endpoint orchestrates the pass-the-hash authentication over SMB port 445, establishing an administrative session on the target server. LateralMovementEvents capture the cross-host movement showing source_host: corp-ws-055, destination_host: srv-file-012, protocol: SMB, auth_method: NTLM_PTH. The domain controller also logs Event ID 4624 (Logon Type 3 - Network) in WindowsSecu |
| 4 | Defense Evasion | `T1562.001` | Impair Defenses: Disable or Modify Tools | On the critical server, the attacker disables Windows Defender real-time monitoring and endpoint detection tools (T1562.001) via the windows-endpoint /defender/disable endpoint. This executes: "Set-MpPreference -DisableRealtimeMonitoring $true", "sc stop WinDefend", and registry modifications to HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware=1. DeviceProcessEvents records the PowerShell execution, service state changes, and registry writes on srv-file-012. |
| 5 | Impact | `T1486` | Data Encrypted for Impact | With defenses neutralized, the attacker deploys ransomware (T1486) on the server. First, Volume Shadow Copies are deleted via the windows-endpoint /vss/delete endpoint (vssadmin delete shadows /all /quiet). Then the ransomware payload encrypts critical files using /file/modify to rename files with a .locked extension and /file/create to drop ransom notes (README_RESTORE.txt) in each directory. DeviceProcessEvents on srv-file-012 records extensive file rename operations (thousands of FileModified events with .locked extension) and the ransom note file creation events. |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1018` | User Account Management | T1078 (Valid Accounts), T1562.001 (Impair Defenses: Disable or Modify Tools) | Apply least privilege; periodically review role assignments and remove unused accounts. |
| `M1022` | Restrict File and Directory Permissions | T1562.001 (Impair Defenses: Disable or Modify Tools) | Protect security-tool binaries and registry keys from tampering. |
| `M1027` | Password Policies | T1078 (Valid Accounts) | Enforce strong, rotated credentials and disable inactive / stale accounts. |
| `M1032` | Multi-factor Authentication | T1078 (Valid Accounts) | Require MFA on all human and service identities, especially for privileged roles and OAuth grants. |
