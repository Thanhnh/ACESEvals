# Recon Agent Report — incident_55_v4

**Domain Credential Logon → AD Enumeration → WMI Lateral Movement → Defender Disable → Ransomware**

Variant 4 of a ransomware attack chain initiated through compromised valid domain
credentials. The attacker authenticates to a workstation using stolen domain credentials,
enumerates Active Directory to identify high-value servers, then pivots via WMI lateral
movement to a critical server. On the target host the attacker disables Microsoft Defender
endpoint security before deploying ransomware that encrypts critical business data.
This variant distinguishes itself from prior variants by performing defense evasion
on the target rather than the entry point, and by using WMI as the lateral movement
mechanism.

_Generated: 2026-07-15T19:11:41+00:00_

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

**Kill chain:** Initial Access → Discovery → Lateral Movement → Defense Evasion → Impact

**Entry point:** Domain logon to workstation using compromised valid domain credentials

**Final objective:** Ransomware deployment encrypting critical business data on target server


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1078.002` | Valid Accounts: Domain Accounts | A threat actor possessing previously compromised domain credentials for user jmorales@CONTOSO.LOCAL authenticates to employee workstation ws-entry-04 using Valid Accounts: Domain Accounts (T1078.002). The attacker initiates a Kerberos AS-REQ against domain controller contoso-dc01, receiving a valid TGT. The resulting logon generates Windows Security EventID 4624 (LogonType 10 - RemoteInteractive) on the workstation and EventID 4768 (Kerberos TGT request) on the domain controller. The logon appears legitimate given valid credential material. The jmorales account is a member of Domain Admins — a |
| 2 | Discovery | `T1018` | Remote System Discovery | From the compromised workstation session, the attacker performs Remote System Discovery (T1018) by issuing LDAP queries against contoso-dc01. The queries enumerate computer objects (objectClass=computer) filtered by operatingSystem containing "Server" and servicePrincipalName attributes. This generates EventID 4662 (directory service object access) entries in WindowsSecurityEvents. The enumeration identifies srv-critical-01 as a high-value file server hosting Finance$, HR$, and Backup$ shares containing critical business data. |
| 3 | Lateral Movement | `T1047` | Windows Management Instrumentation | The attacker leverages Windows Management Instrumentation (T1047) for lateral movement from ws-entry-04 to srv-critical-01. Using the domain credentials which hold local administrator membership on the target server (due to Domain Admins group membership and absence of tiered administration), the attacker connects via DCOM (TCP port 135 for RPC endpoint mapper, then dynamic RPC port in 49152-65535 range) and invokes Win32_Process.Create to spawn a process on the remote host. The flat network topology provides no segmentation between the workstation subnet (172.30.10.0/24) and server subnet (17 |
| 4 | Defense Evasion | `T1562.001` | Impair Defenses: Disable or Modify Tools | Unlike prior variants that disabled security on the entry workstation, this variant performs defense evasion (T1562.001) specifically on the TARGET server srv-critical-01. The attacker executes PowerShell via the WMI-spawned session: Set-MpPreference -DisableRealtimeMonitoring $true, followed by sc.exe stop WinDefend. These commands disable Microsoft Defender real-time scanning. This is possible because Tamper Protection is NOT enforced on srv-critical-01, allowing any local admin to modify Defender settings. DeviceProcessEvents captures the full process chain: WmiPrvSE.exe → powershell.exe →  |
| 5 | Impact | `T1486` | Data Encrypted for Impact | With endpoint protection disabled on srv-critical-01, the attacker deploys a ransomware binary. The ransomware enumerates accessible file shares (Finance$, HR$, Backup$) and local directories, encrypting documents, spreadsheets, databases, and backup files with a .locked extension. DeviceFileEvents captures the mass FileRenamed actions as each file gains the .locked extension — hundreds of rename events in under 60 seconds. DeviceProcessEvents shows the ransomware process performing high-volume file I/O. The ransomware drops a README_DECRYPT.txt ransom note in each affected directory (DeviceFi |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1018` | User Account Management | T1078.002 (Valid Accounts: Domain Accounts), T1562.001 (Impair Defenses: Disable or Modify Tools) | Apply least privilege; periodically review role assignments and remove unused accounts. |
| `M1022` | Restrict File and Directory Permissions | T1562.001 (Impair Defenses: Disable or Modify Tools) | Protect security-tool binaries and registry keys from tampering. |
| `M1027` | Password Policies | T1078.002 (Valid Accounts: Domain Accounts) | Enforce strong, rotated credentials and disable inactive / stale accounts. |
| `M1032` | Multi-factor Authentication | T1078.002 (Valid Accounts: Domain Accounts) | Require MFA on all human and service identities, especially for privileged roles and OAuth grants. |
