# Recon Agent Report — incident_322_v1

**Spearphishing → C2 Proxy → NTDS Dump → Hybrid Identity Sync → ARM Resource Hijacking**

Hybrid identity compromise targeting AlpineSkiHouse. An attacker spearphishes
a user with a malicious attachment, establishes C2 beaconing through a proxy,
enumerates ARM resources using the victim's cached Azure session, escalates by
dumping NTDS.dit via ntdsutil on the domain controller, authenticates to Azure AD
through hybrid identity sync with harvested domain admin credentials, and deploys
cryptomining VMs through ARM operations (resource hijacking).

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
| AD Domain | `ALPINESKIHOUSE.LOCAL` | `` | On-prem AD domain (NetBIOS `ALPINESKIHOUSE`); baseline. |
| AD User | `Administrator` | `ALPINESKIHOUSE.LOCAL` | Member of Domain Admins, Administrators; enabled. |
| AD User | `krbtgt` | `ALPINESKIHOUSE.LOCAL` | Member of no groups; disabled. |
| AD User | `svc_backup` | `ALPINESKIHOUSE.LOCAL` | Member of Backup Operators, Service Accounts; enabled. |
| AD User | `svc_sql` | `ALPINESKIHOUSE.LOCAL` | Member of Service Accounts; enabled. |
| AD User | `john.doe` | `ALPINESKIHOUSE.LOCAL` | Member of Domain Users, IT Support; enabled. |
| AD User | `jane.smith` | `ALPINESKIHOUSE.LOCAL` | Member of Domain Users, HR; enabled. |
| AD User | `admin.ops` | `ALPINESKIHOUSE.LOCAL` | Member of Domain Admins, IT Support; enabled. |
| AD Group | `Domain Admins` | `ALPINESKIHOUSE.LOCAL` | Members: Administrator, admin.ops. |
| AD Group | `Domain Users` | `ALPINESKIHOUSE.LOCAL` | Members: john.doe, jane.smith. |
| AD Group | `Service Accounts` | `ALPINESKIHOUSE.LOCAL` | Members: svc_backup, svc_sql. |
| AD Group | `Backup Operators` | `ALPINESKIHOUSE.LOCAL` | Members: svc_backup. |
| SPN | `cifs/dc.alpineskihouse.local` | `DC$` | SPN bound to account `DC$`. |
| SPN | `ldap/dc.alpineskihouse.local` | `DC$` | SPN bound to account `DC$`. |
| SPN | `MSSQLSvc/sql01.alpineskihouse.local:1433` | `svc_sql` | SPN bound to account `svc_sql`. |
| SPN | `HTTP/web01.alpineskihouse.local` | `svc_web` | SPN bound to account `svc_web`. |
| Computer | `DC` | `ALPINESKIHOUSE.LOCAL` | Windows Server 2022 @ 172.30.10.60. |
| Computer | `WEB01` | `ALPINESKIHOUSE.LOCAL` | Windows Server 2022 @ 172.30.20.10. |
| Computer | `SQL01` | `ALPINESKIHOUSE.LOCAL` | Windows Server 2022 @ 172.30.10.50. |

## Expected Attack Path

**Kill chain:** Initial Access → Command and Control → Discovery → Credential Access → Privilege Escalation → Impact

**Entry point:** Spearphishing attachment targeting AlpineSkiHouse user

**Final objective:** Deploy cryptomining VMs via ARM resource hijacking


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1566.001` | Phishing: Spearphishing Attachment | A threat actor targets an employee (jsmith) at AlpineSkiHouse with a spearphishing email containing a malicious document attachment delivered via Exchange Online. Upon opening the attachment on workstation ASH-WS01, the embedded payload executes and establishes a command-and-control beacon that communicates through an HTTP proxy, providing persistent remote access to the compromised endpoint. |
| 2 | Command and Control | `T1071.001` | Application Layer Protocol: Web Protocols | Operating through the C2 channel, the attacker discovers a cached Azure session (browser tokens or Azure CLI token cache) on ASH-WS01 and leverages it to enumerate ARM resources — listing subscriptions, resource groups, and compute quotas to map the organization's cloud infrastructure and identify cryptomining targets. |
| 3 | Discovery | `T1580` | Cloud Infrastructure Discovery | The attacker then pivots to the domain controller (ASH-DC01), executing ntdsutil to create an IFM (Install From Media) snapshot and extract the NTDS.dit database. This yields NTLM hashes for all domain accounts, including the domain administrator whose credentials are synchronized to Azure AD through Azure AD Connect hybrid identity. |
| 4 | Credential Access | `T1003.003` | OS Credential Dumping: NTDS | Using the domain admin's NTLM hash, the attacker authenticates to Azure AD via the hybrid identity sync pathway (pass-the-hash against the AD Connect service account or direct cloud auth with cracked password), obtaining a Global Administrator token. With this elevated Azure AD access, the attacker deploys multiple GPU-optimized virtual machines across several regions through ARM API calls, configuring them for cryptocurrency mining — constituting resource hijacking that generates significant financial impact to the organization. |
| 5 | Privilege Escalation | `T1078.004` | Valid Accounts: Cloud Accounts |  |
| 6 | Impact | `T1496` | Resource Hijacking |  |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1017` | User Training | T1566.001 (Phishing: Spearphishing Attachment) | Train users to identify malicious attachments and report them quickly. |
| `M1018` | User Account Management | T1580 (Cloud Infrastructure Discovery), T1078.004 (Valid Accounts: Cloud Accounts) | Deny ListKeys at the policy level; require RBAC + just-in-time elevation. |
| `M1021` | Restrict Web-Based Content | T1566.001 (Phishing: Spearphishing Attachment) | Block execution of mounted ISO contents and unsigned executables from email. |
| `M1026` | Privileged Account Management | T1078.004 (Valid Accounts: Cloud Accounts) | Use Privileged Identity Management (PIM) just-in-time access for high-value cloud roles. |
| `M1027` | Password Policies | T1078.004 (Valid Accounts: Cloud Accounts) | Enforce strong, rotated credentials and disable inactive / stale accounts. |
| `M1031` | Network Intrusion Prevention | T1566.001 (Phishing: Spearphishing Attachment), T1071.001 (Application Layer Protocol: Web Protocols) | Detonate inbound attachments in a sandbox; block ISO / LNK / HTA where possible. |
| `M1032` | Multi-factor Authentication | T1078.004 (Valid Accounts: Cloud Accounts) | Require MFA / Conditional Access on every cloud sign-in, including service principals where supported. |
| `M1037` | Filter Network Traffic | T1071.001 (Application Layer Protocol: Web Protocols) | Restrict egress to allow-listed FQDNs and alert on anomalous beacons. |
| `M1047` | Audit | T1580 (Cloud Infrastructure Discovery) | Alert on high-volume ARM enumeration (listKeys, listResources) by non-automation principals. |
