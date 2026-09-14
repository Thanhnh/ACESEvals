# Recon Agent Report — incident_55_v1

**Valid Domain Credentials → LSASS Dump → SMB Lateral Movement → Ransomware Deployment**

An attacker leverages compromised valid domain credentials to gain initial access
to a corporate workstation. After authenticating via the domain controller, the
attacker dumps LSASS process memory to extract domain administrator NTLM hashes,
then laterally moves via SMB admin shares to a critical file server. On the target
server, the attacker disables Windows Defender real-time protection to evade
endpoint detection before deploying ransomware that encrypts critical business data.

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
| AD Domain | `YOURORG.LOCAL` | `` | On-prem AD domain (NetBIOS `YOURORG`); baseline. |
| AD User | `Administrator` | `YOURORG.LOCAL` | Member of Domain Admins, Administrators; enabled. |
| AD User | `krbtgt` | `YOURORG.LOCAL` | Member of no groups; disabled. |
| AD User | `svc_backup` | `YOURORG.LOCAL` | Member of Backup Operators, Service Accounts; enabled. |
| AD User | `svc_sql` | `YOURORG.LOCAL` | Member of Service Accounts; enabled. |
| AD User | `john.doe` | `YOURORG.LOCAL` | Member of Domain Users, IT Support; enabled. |
| AD User | `jane.smith` | `YOURORG.LOCAL` | Member of Domain Users, HR; enabled. |
| AD User | `admin.ops` | `YOURORG.LOCAL` | Member of Domain Admins, IT Support; enabled. |
| AD Group | `Domain Admins` | `YOURORG.LOCAL` | Members: Administrator, admin.ops. |
| AD Group | `Domain Users` | `YOURORG.LOCAL` | Members: john.doe, jane.smith. |
| AD Group | `Service Accounts` | `YOURORG.LOCAL` | Members: svc_backup, svc_sql. |
| AD Group | `Backup Operators` | `YOURORG.LOCAL` | Members: svc_backup. |
| SPN | `cifs/dc.yourorg.local` | `DC$` | SPN bound to account `DC$`. |
| SPN | `ldap/dc.yourorg.local` | `DC$` | SPN bound to account `DC$`. |
| SPN | `MSSQLSvc/sql01.yourorg.local:1433` | `svc_sql` | SPN bound to account `svc_sql`. |
| SPN | `HTTP/web01.yourorg.local` | `svc_web` | SPN bound to account `svc_web`. |
| Computer | `DC` | `YOURORG.LOCAL` | Windows Server 2022 @ 172.30.10.60. |
| Computer | `WEB01` | `YOURORG.LOCAL` | Windows Server 2022 @ 172.30.20.10. |
| Computer | `SQL01` | `YOURORG.LOCAL` | Windows Server 2022 @ 172.30.10.50. |

## Expected Attack Path

**Kill chain:** Initial Access → Credential Access → Lateral Movement → Defense Evasion → Impact

**Entry point:** Authentication with compromised valid domain credentials (YOURORG\jsmith)

**Final objective:** Deploy ransomware encrypting critical business data on YOURORG-FS01


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1078.002` | Valid Accounts: Domain Accounts | A threat actor who has previously obtained valid domain credentials for user jsmith (YOURORG\jsmith) initiates a Remote Desktop session to the corporate workstation YOURORG-WKS01. The domain controller YOURORG-DC01 processes a Kerberos AS-REQ and issues a TGT for jsmith, generating WindowsSecurityEvents with EventID 4768 on the DC. The workstation logs EventID 4624 (LogonType 10 - RemoteInteractive) with Account "YOURORG\jsmith", IpAddress showing the attacker's source, and AuthenticationPackageName "Kerberos". EventID 4672 is also logged indicating special privileges assigned to the session.  |
| 2 | Credential Access | `T1003.001` | OS Credential Dumping: LSASS Memory | Once on the workstation with a valid interactive session, the attacker escalates by targeting the LSASS process. A domain administrator had previously authenticated to this workstation (due to lack of tiered admin model), leaving cached NTLM credentials in LSASS memory. The attacker executes: rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass_pid> C:\temp\debug.dmp full. This generates DeviceProcessEvents with FileName "rundll32.exe", ProcessCommandLine containing "comsvcs" and "MiniDump", InitiatingProcessFileName "cmd.exe", DeviceName "YOURORG-WKS01", and AccountName "jsmith". A co |
| 3 | Lateral Movement | `T1021.002` | Remote Services: SMB/Windows Admin Shares | Armed with the domain administrator NTLM hash, the attacker performs lateral movement using pass-the-hash over SMB. The lateral-movement service records the cross-host pivot in LateralMovementEvents with SourceHost "YOURORG-WKS01", TargetHost "YOURORG-FS01", MovementType "SMB", AccountUsed "DomainAdmin", AccountDomain "YOURORG", AuthenticationType "PassTheHash", ShareName "C$", Port 445, and Success true. The file server logs WindowsSecurityEvents EventID 4624 with LogonType 3 (Network), Account "YOURORG\DomainAdmin", AuthenticationPackageName "NTLM", and WorkstationName "YOURORG-WKS01". Event |
| 4 | Defense Evasion | `T1562.001` | Impair Defenses: Disable or Modify Tools | On YOURORG-FS01, now executing with domain administrator privileges, the attacker disables Windows Defender real-time protection. DeviceProcessEvents captures FileName "powershell.exe" with ProcessCommandLine "Set-MpPreference -DisableRealtimeMonitoring $true", DeviceName "YOURORG-FS01", AccountName "DomainAdmin". A second DeviceProcessEvents entry shows FileName "sc.exe" with ProcessCommandLine "stop WinDefend". The MDATP engine generates AlertInfo with Title "Tampering with Microsoft Defender" and Category "DefenseEvasion" and Severity "High". |
| 5 | Impact | `T1486` | Data Encrypted for Impact | With endpoint protection neutralized, the attacker deploys a ransomware payload. DeviceProcessEvents logs FileName "ransomware.exe" with InitiatingProcessFileName "cmd.exe" on DeviceName "YOURORG-FS01". The ransomware first deletes Volume Shadow Copies — DeviceProcessEvents shows FileName "vssadmin.exe" with ProcessCommandLine "delete shadows /all /quiet". Then mass encryption begins — DeviceFileEvents on YOURORG-FS01 shows hundreds of ActionType "FileRenamed" events where files gain the ".lockbit" extension. The MDATP engine generates a critical AlertInfo with Title "Ransomware activity detec |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1018` | User Account Management | T1078.002 (Valid Accounts: Domain Accounts), T1562.001 (Impair Defenses: Disable or Modify Tools) | Apply least privilege; periodically review role assignments and remove unused accounts. |
| `M1022` | Restrict File and Directory Permissions | T1562.001 (Impair Defenses: Disable or Modify Tools) | Protect security-tool binaries and registry keys from tampering. |
| `M1027` | Password Policies | T1078.002 (Valid Accounts: Domain Accounts) | Enforce strong, rotated credentials and disable inactive / stale accounts. |
| `M1032` | Multi-factor Authentication | T1078.002 (Valid Accounts: Domain Accounts) | Require MFA on all human and service identities, especially for privileged roles and OAuth grants. |
