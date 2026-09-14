# Recon Agent Report — incident_322_v3

**Front Door WAF Exploit → Domain Credential Abuse → DC-Routed RDP → C2 Beacon**

Variant 3 of an external exploitation-to-C2 attack chain. A threat actor identifies and
exploits a public-facing web application (CVE-based RCE) behind an Azure Front Door WAF
to gain initial code execution on the underlying Windows server. The attacker discovers
valid domain administrator credentials stored on the compromised host and abuses them for
privilege escalation. Using elevated domain access, the attacker queries Active Directory
to enumerate high-value internal targets, then moves laterally via RDP — routing through
the domain controller infrastructure rather than direct host-to-host movement. Finally,
the attacker establishes persistent command and control via application layer protocol,
registering a beacon on the target server for ongoing access.

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

**Kill chain:** Initial Access → Privilege Escalation → Discovery → Lateral Movement → Command and Control

**Entry point:** Exploitation of public-facing web application behind Azure Front Door WAF

**Final objective:** Establish persistent C2 beacon via application layer protocol on high-value internal server


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1190` | Exploit Public-Facing Application | A threat actor conducts reconnaissance against a public-facing web application hosted behind Azure Front Door with WAF protection. The attacker identifies a vulnerability in the backend application (web-srv-01.contoso.local) and crafts a request that bypasses or triggers WAF rules while achieving remote code execution on the underlying Windows Server. |
| 2 | Privilege Escalation | `T1078` | Valid Accounts | CommonSecurityLog records the exploit attempt with WAF detection events showing the malicious payload in RequestURL and DeviceAction fields. The WAF may log the attack as DeviceEventClassID matching known exploit signatures but fails to block the request due to an evasion technique. |
| 3 | Discovery | `T1018` | Remote System Discovery | Upon gaining code execution (webshell or reverse shell), the attacker enumerates the local host and discovers domain administrator credentials stored in an accessible location — such as a web.config file, a scheduled task running as a domain admin, or cached credentials in LSASS. SecurityEvent records show EventID 4624 (successful logon) with LogonType 3 (network) from web-srv-01 to CONTOSO-DC01, using the discovered domain admin account (da-admin@CONTOSO.LOCAL). EventID 4672 confirms special privilege assignment for the new logon session. |
| 4 | Lateral Movement | `T1021.001` | Remote Services: Remote Desktop Protocol | With domain admin access to the domain controller, the attacker queries Active Directory to enumerate computer objects, organizational units, and identify high-value server targets. SecurityEvent captures LDAP query activity and additional EventID 4624 entries showing the enumeration session from the compromised account. |
| 5 | Command and Control | `T1071` | Application Layer Protocol | The attacker then initiates an RDP session from the domain controller to the high-value target server (data-srv-01). SecurityEvent records show EventID 4624 with LogonType 10 (RemoteInteractive) on data-srv-01, with SourceComputerName pointing to CONTOSO-DC01. EventID 4648 on CONTOSO-DC01 shows the explicit credential usage for the outbound RDP connection. This DC-routed path differs from previous variants that used direct host-to-host lateral movement. |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1016` | Vulnerability Scanning | T1190 (Exploit Public-Facing Application) | Continuously scan public surfaces and validate fixes. |
| `M1018` | User Account Management | T1078 (Valid Accounts) | Apply least privilege; periodically review role assignments and remove unused accounts. |
| `M1027` | Password Policies | T1078 (Valid Accounts) | Enforce strong, rotated credentials and disable inactive / stale accounts. |
| `M1030` | Network Segmentation | T1190 (Exploit Public-Facing Application) | Isolate exposed workloads from sensitive backends; use private endpoints. |
| `M1032` | Multi-factor Authentication | T1078 (Valid Accounts) | Require MFA on all human and service identities, especially for privileged roles and OAuth grants. |
| `M1050` | Exploit Protection | T1190 (Exploit Public-Facing Application) | Enable WAF / RASP and runtime protections for exposed application endpoints. |
| `M1051` | Update Software | T1190 (Exploit Public-Facing Application) | Patch internet-facing applications promptly; track CVEs against deployed versions. |
