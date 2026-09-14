# Recon Agent Report — incident_38_v3

**IIS Exploit → Kerberoasting → WMI Lateral → DCSync Domain Dominance**

A threat actor exploits a public-facing IIS web application to gain initial code execution
on a Windows Server. After establishing persistence with an ASPX web shell and disabling
Windows Defender for defense evasion, the attacker performs Kerberoasting to crack service
account credentials offline. Using those cracked credentials, the attacker leverages WMI
for lateral movement to the domain controller, executes DCSync to replicate all domain
password hashes, and establishes persistence via a scheduled task. This variant (v3) uses
Kerberoasting for credential access and WMI for lateral movement, achieving full domain
dominance through DCSync — differing from v1 (LSASS + SMB/PsExec) and v2 (LSASS + RDP).

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
| Credential (password) | `WEBSHELL_ACCESS` | `windows-endpoint, domain-controller` | Seeded password planted into the cyber range. Grants access to: windows-endpoint, domain-controller. |
| Credential (password) | `SVC_ACCOUNT_CREDS` | `lateral-movement, domain-controller` | Seeded password planted into the cyber range. Grants access to: lateral-movement, domain-controller. |

## Expected Attack Path

**Kill chain:** Initial Access → Defense Evasion → Credential Access → Lateral Movement → Credential Access → Persistence

**Entry point:** Exploitation of public-facing IIS web application (CVE-based RCE)

**Final objective:** Domain dominance via DCSync — replicate all domain password hashes


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1190` | Exploit Public-Facing Application | ## Phase 1: Initial Access (T1190 + T1505.003) A threat actor identifies a public-facing IIS web application on iis-websvr01.contoso.local running a vulnerable ASP.NET component. The attacker exploits a deserialization or file upload vulnerability to achieve remote code execution under the IIS application pool identity (IIS_APPPOOL). The attacker immediately deploys an ASPX web shell (e.g., China Chopper variant) to C:\inetpub\wwwroot\error_handler.aspx for persistent command execution. |
| 2 | Persistence | `T1505.003` | Server Software Component: Web Shell | Detection evidence in DeviceProcessEvents: - w3wp.exe (PID: parent) spawns cmd.exe /c whoami (child) - File creation: C:\inetpub\wwwroot\error_handler.aspx - ProcessCommandLine contains encoded PowerShell or certutil download |
| 3 | Defense Evasion | `T1562.001` | Impair Defenses: Disable or Modify Tools | ## Phase 2: Defense Evasion (T1562.001) Using the web shell, the attacker disables Windows Defender real-time protection via PowerShell (Set-MpPreference -DisableRealtimeMonitoring $true) and stops the WinDefend service (sc.exe stop WinDefend). This ensures subsequent credential access tooling (Rubeus, Invoke-Kerberoast) executes without AV detection. |
| 4 | Credential Access | `T1558.003` | Steal or Forge Kerberos Tickets: Kerberoasting | Detection evidence in DeviceProcessEvents: - w3wp.exe → cmd.exe → powershell.exe -c Set-MpPreference -DisableRealtimeMonitoring $true - w3wp.exe → cmd.exe → sc.exe stop WinDefend - FileName: powershell.exe, ProcessCommandLine contains "MpPreference" or "WinDefend" |
| 5 | Lateral Movement | `T1047` | Windows Management Instrumentation | ## Phase 3: Credential Access — Kerberoasting (T1558.003) The attacker enumerates Service Principal Names (SPNs) registered in Active Directory using setspn.exe -Q */* or LDAP queries against contoso-dc01. For each discovered SPN (e.g., MSSQLSvc/sqlserver.contoso.local:1433, HTTP/webapp.contoso.local), the attacker requests TGS service tickets using the compromised host's domain machine account. Tickets are requested with RC4 encryption (TicketEncryptionType 0x17), which enables offline password cracking. The attacker extracts tickets and cracks them using hashcat (mode 13100), recovering the  |
| 6 | Credential Access | `T1003.006` | OS Credential Dumping: DCSync | Detection evidence in WindowsSecurityEvents (on contoso-dc01): - EventID 4769: Multiple Kerberos Service Ticket Operations - TicketEncryptionType: 0x17 (RC4-HMAC, weak encryption) - ServiceName: MSSQLSvc/sqlserver.contoso.local, HTTP/webapp.contoso.local - IpAddress: <iis-websvr01 IP> (single source requesting multiple SPNs) - Account: IIS-WEBSVR01$ (machine account) or compromised user |
| 7 | Persistence | `T1053.005` | Scheduled Task/Job: Scheduled Task | ## Phase 4: Lateral Movement — WMI (T1047) With the cracked service account credentials (SVC_SQLSVC / P@ssw0rd123), the attacker uses Windows Management Instrumentation (WMI) to execute commands remotely on the domain controller (contoso-dc01). The command is initiated from iis-websvr01 using wmic.exe: wmic /node:contoso-dc01 /user:CONTOSO\SVC_SQLSVC process call create "cmd.exe /c ..." |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1016` | Vulnerability Scanning | T1190 (Exploit Public-Facing Application) | Continuously scan public surfaces and validate fixes. |
| `M1018` | User Account Management | T1562.001 (Impair Defenses: Disable or Modify Tools) | Restrict who can disable EDR, Defender, or audit logs; require break-glass approval. |
| `M1022` | Restrict File and Directory Permissions | T1562.001 (Impair Defenses: Disable or Modify Tools) | Protect security-tool binaries and registry keys from tampering. |
| `M1030` | Network Segmentation | T1190 (Exploit Public-Facing Application) | Isolate exposed workloads from sensitive backends; use private endpoints. |
| `M1050` | Exploit Protection | T1190 (Exploit Public-Facing Application) | Enable WAF / RASP and runtime protections for exposed application endpoints. |
| `M1051` | Update Software | T1190 (Exploit Public-Facing Application) | Patch internet-facing applications promptly; track CVEs against deployed versions. |
