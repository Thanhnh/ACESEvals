# Recon Agent Report — incident_38_v2

**Front Door WAF Bypass → App Service RCE → Web Shell Persistence → Lateral Movement → Data Collection**

Multi-stage web exploitation attack targeting a public-facing Azure App Service behind
Azure Front Door WAF. The attacker crafts requests that bypass WAF rules and exploits a
vulnerability in the web application (T1190) to achieve remote code execution. In this
variant (persistence-first ordering), the attacker immediately deploys a persistent web
shell (T1505.003) to secure ongoing access before any further exploration. Using the web
shell as a stable foothold, the attacker pivots laterally to an internal Windows endpoint
via remote services (T1021). From the compromised endpoint, the attacker performs internal
reconnaissance to map the network environment (T1018) and collects sensitive data from
accessible local systems (T1005).

_Generated: 2026-07-14T17:56:54+00:00_

## Entity Inventory

| Resource Type | Name | Parent Resource | Description |
|---|---|---|---|
| Subscription | `SABER-Sim Subscription` | `` | Subscription `12345678-1234-1234-1234-123456789abc` in tenant `87654321-4321-4321-4321-cba987654321`; baseline. |
| Tenant | `87654321-4321-4321-4321-cba987654321` | `SABER-Sim Subscription` | Azure AD tenant; baseline. |
| Resource Group | `production-rg` | `SABER-Sim Subscription` | Resource group in `eastus`; baseline. |
| Resource Group | `development-rg` | `SABER-Sim Subscription` | Resource group in `eastus`; baseline. |
| App Service | `prod-webapp` | `production-rg` | node 20 app service; baseline. |
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
| Credential (password) | `SERVICE_ACCOUNT_CREDS` | `lateral-movement` | Seeded password planted into the cyber range. Grants access to: lateral-movement. |

## Expected Attack Path

**Kill chain:** Initial Access → Persistence → Lateral Movement → Discovery → Collection

**Entry point:** WAF bypass and exploitation of public-facing Azure App Service web application

**Final objective:** Collect sensitive data from internal Windows endpoint after lateral movement


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1190` | Exploit Public-Facing Application | A threat actor identifies a public-facing Azure App Service web application protected by Azure Front Door with WAF policies. The attacker performs reconnaissance on the application, discovering it runs a vulnerable web framework behind the WAF. |
| 2 | Persistence | `T1505.003` | Server Software Component: Web Shell | **Step 1 — Initial Access (T1190):** The attacker crafts HTTP requests designed to bypass Azure Front Door WAF rules using encoding tricks, header manipulation, or request smuggling techniques. The malicious payload exploits a remote code execution vulnerability in the web application (such as deserialization, template injection, or file upload bypass). The exploit succeeds, granting the attacker command execution on the App Service instance. This generates anomalous entries in AppServiceHTTPLogs showing unusual URI patterns (CsUriStem containing encoded payloads), non-standard UserAgent strin |
| 3 | Lateral Movement | `T1021` | Remote Services | **Step 2 — Persistence (T1505.003):** Immediately after gaining RCE (before any lateral movement or reconnaissance), the attacker deploys a persistent web shell to the App Service filesystem. This persistence-first approach ensures continued access even if the initial vulnerability is patched. The web shell is placed in a web-accessible directory (e.g., /site/wwwroot/uploads/handler.aspx) disguised as a legitimate application file. Subsequent web shell access appears in AppServiceHTTPLogs as repeated POST requests to the shell endpoint with consistent CsUriStem patterns, CsMethod=POST, varying |
| 4 | Discovery | `T1018` | Remote System Discovery | **Step 3 — Lateral Movement (T1021):** Using the stable web shell access, the attacker enumerates the App Service environment variables and configuration files, discovering stored service account credentials (connection strings containing passwords, or plaintext credentials in web.config). With these credentials, the attacker pivots to an internal Windows endpoint (corp-workstation01) using remote services. LateralMovementEvents capture the cross-host connection with SourceHost=corp-webserver, TargetHost=corp-workstation01, MovementType indicating the protocol used (SMB/WMI/PsExec), and the Ac |
| 5 | Collection | `T1005` | Data from Local System | **Step 4 — Discovery (T1018):** From the compromised Windows endpoint, the attacker performs internal reconnaissance to understand the network environment. Commands executed include "net view /domain" (enumerate domain systems), "nltest /dclist:CONTOSO.LOCAL" (find domain controllers), "arp -a" (discover local network hosts), "nslookup" queries for internal DNS entries, and "net group 'Domain Admins' /domain" (enumerate privileged accounts). DeviceProcessEvents logs capture each execution with FileName (cmd.exe, net.exe, nltest.exe, nslookup.exe), full ProcessCommandLine arguments, InitiatingP |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1016` | Vulnerability Scanning | T1190 (Exploit Public-Facing Application) | Continuously scan public surfaces and validate fixes. |
| `M1030` | Network Segmentation | T1190 (Exploit Public-Facing Application) | Isolate exposed workloads from sensitive backends; use private endpoints. |
| `M1050` | Exploit Protection | T1190 (Exploit Public-Facing Application) | Enable WAF / RASP and runtime protections for exposed application endpoints. |
| `M1051` | Update Software | T1190 (Exploit Public-Facing Application) | Patch internet-facing applications promptly; track CVEs against deployed versions. |
