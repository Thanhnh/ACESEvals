# Recon Agent Report — incident_38_v4

**Front Door Exploit → Web Shell → Internal Recon → Lateral Movement → Data Collection**

Multi-stage web exploitation attack targeting a public-facing Azure App Service
behind Azure Front Door. The attacker exploits a vulnerability in the web application
(T1190), deploys a web shell for persistent access (T1505.003), conducts internal
network reconnaissance to identify lateral movement targets, pivots to an internal
Windows server via remote services (T1021), and collects sensitive data from the
compromised host. Variant 4 uses a different attack chain sequence with
reconnaissance-driven lateral movement via WMI remote services rather than the
credential-first pivot paths used in prior variants.

_Generated: 2026-07-14T17:56:53+00:00_

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
| Credential (password) | `WEB_SHELL_ACCESS` | `azure-app-service` | Seeded password planted into the cyber range. Grants access to: azure-app-service. |
| Credential (password) | `INTERNAL_SERVICE_CREDENTIALS` | `lateral-movement, windows-endpoint` | Seeded password planted into the cyber range. Grants access to: lateral-movement, windows-endpoint. |

## Expected Attack Path

**Kill chain:** Initial Access → Persistence → Discovery → Lateral Movement → Collection

**Entry point:** Exploitation of public-facing web application behind Azure Front Door

**Final objective:** Data collection from compromised internal Windows server


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1190` | Exploit Public-Facing Application | A threat actor targets a public-facing web application hosted on Azure App Service, protected by Azure Front Door with WAF capabilities. The attacker crafts malicious requests that bypass WAF rules and exploit a remote code execution vulnerability in the application framework (T1190), gaining initial code execution on the App Service instance. Evidence of the exploitation attempt appears in FrontDoorAccessLog and FrontDoorWebApplicationFirewallLog as the WAF detects but fails to fully block the malicious payload. |
| 2 | Persistence | `T1505.003` | Server Software Component: Web Shell | With code execution established, the attacker deploys a web shell (T1505.003) into the application directory, providing persistent command-and-control access that survives application restarts. The web shell is accessible via standard HTTP requests that blend with normal application traffic, generating entries in AppServiceHTTPLogs with distinctive POST patterns to the shell endpoint. |
| 3 | Discovery | `T1046` | Network Service Scanning | From the web shell, the attacker conducts internal network service scanning (T1046) to enumerate reachable hosts and services within the virtual network. This reconnaissance discovers an internal Windows server with exposed WMI management interfaces and reveals service account credentials stored in the application configuration environment variables. The scanning triggers SecurityAlert detections from Microsoft Defender for Cloud. |
| 4 | Lateral Movement | `T1021` | Remote Services | Using the discovered credentials, the attacker performs lateral movement via WMI remote services (T1021) to the internal Windows server. This variant's lateral movement path uses WMI execution rather than SMB or RDP connections used in previous variants, producing distinct DeviceProcessEvents telemetry as wmiprvse.exe spawns attacker-controlled processes on the target host. |
| 5 | Collection | `T1005` | Data from Local System | Once on the internal Windows server with administrative access, the attacker collects sensitive data from the local file system (T1005), including proprietary documents, configuration files with additional credentials, and business-critical data stored on local drives. The collection activity generates DeviceProcessEvents as the attacker uses command-line tools to enumerate directories and stage files for exfiltration. |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1016` | Vulnerability Scanning | T1190 (Exploit Public-Facing Application) | Continuously scan public surfaces and validate fixes. |
| `M1030` | Network Segmentation | T1190 (Exploit Public-Facing Application) | Isolate exposed workloads from sensitive backends; use private endpoints. |
| `M1050` | Exploit Protection | T1190 (Exploit Public-Facing Application) | Enable WAF / RASP and runtime protections for exposed application endpoints. |
| `M1051` | Update Software | T1190 (Exploit Public-Facing Application) | Patch internet-facing applications promptly; track CVEs against deployed versions. |
