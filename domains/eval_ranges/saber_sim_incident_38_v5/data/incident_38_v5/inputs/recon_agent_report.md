# Recon Agent Report — incident_38_v5

**RSC Prototype Pollution → File Web Shell → IMDS Token Theft → ARM Discovery → Blob Exfiltration**

Multi-stage cloud attack exploiting a prototype pollution vulnerability in React Server
Components (RSC) on an Azure App Service behind Front Door. The attacker achieves RCE
through the RSC endpoint, deploys a file-based web shell for persistent access, explicitly
steals the managed identity token via the IMDS metadata endpoint, performs ARM-based cloud
infrastructure reconnaissance to enumerate storage accounts, and exfiltrates sensitive data
from Azure Blob Storage using the stolen managed identity credentials.

_Generated: 2026-07-14T17:56:53+00:00_

## Entity Inventory

| Resource Type | Name | Parent Resource | Description |
|---|---|---|---|
| Subscription | `SABER-Sim Subscription` | `` | Subscription `12345678-1234-1234-1234-123456789abc` in tenant `87654321-4321-4321-4321-cba987654321`; baseline. |
| Tenant | `87654321-4321-4321-4321-cba987654321` | `SABER-Sim Subscription` | Azure AD tenant; baseline. |
| Resource Group | `production-rg` | `SABER-Sim Subscription` | Resource group in `eastus`; baseline. |
| Resource Group | `development-rg` | `SABER-Sim Subscription` | Resource group in `eastus`; baseline. |
| Storage Account | `proddata001` | `production-rg` | Storage account (Standard_LRS / StorageV2) in `eastus`; baseline. Seeded storage account exposed in the attack surface. |
| Blob Container | `public-assets` | `proddata001` | Public-read container; baseline. |
| Blob | `branding/logo.svg` | `public-assets` | Baseline blob. |
| Blob | `config/app-settings.json` | `public-assets` | Baseline blob. |
| Blob Container | `app-logs` | `proddata001` | Private container; baseline. |
| Blob | `2025/01/application.log` | `app-logs` | Baseline blob. |
| Blob | `2025/01/audit.log` | `app-logs` | Baseline blob. |
| Storage Account | `analyticsdata002` | `development-rg` | Storage account (Standard_GRS / StorageV2) in `westus2`; baseline. |
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
| IMDS-Exposed Token | `managed_identity` | `169.254.169.254` | Managed Identity token reachable via IMDS — exploitable via SSRF. |
| Storage Account (ARM) | `proddata001` | `rg-prod-data` | ARM-visible storage account. |
| Blob Container | `financial-reports` | `proddata001` | Private container. **Weakened**: Key log evidence: - StorageBlobLogs: OperationName=ListContainers, AuthenticationType=OAuth, RequesterObjectId=MI_OBJECT_ID - StorageBlobLogs: OperationName=ListBlobs, ContainerName=financial-reports, StatusCode=200 - StorageBlobLogs: OperationName=GetBlob, multiple blobs, high ResponseBodySize - StorageBlobLogs: CallerIpAddress matches App Service outbound IP - AADSignInLogs: ServicePrincipalId=M |
| Blob | `Q4-2025-revenue.xlsx` | `financial-reports` | Seeded blob. |
| Blob | `annual-forecast-2026.pdf` | `financial-reports` | Seeded blob. |
| Blob Container | `hr-documents` | `proddata001` | Private container. |
| Blob | `employee-records.csv` | `hr-documents` | Seeded blob. |
| Blob | `salary-bands-2026.xlsx` | `hr-documents` | Seeded blob. |
| Blob Container | `customer-data` | `proddata001` | Private container. |
| Blob | `customer-pii-export.json` | `customer-data` | Seeded blob. |

## Expected Attack Path

**Kill chain:** Initial Access → Persistence → Credential Access → Discovery → Collection

**Entry point:** Prototype pollution RCE in React Server Components on Azure App Service behind Front Door

**Final objective:** Exfiltrate sensitive data from Azure Blob Storage using stolen managed identity token


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1190` | Exploit Public-Facing Application | ## Phase 1: Initial Access (T1190) A threat actor discovers a public-facing web application running React Server Components (Next.js RSC) on Azure App Service, exposed through Azure Front Door. The attacker identifies the /_next/rsc endpoint and crafts a malicious RSC payload exploiting a prototype pollution vulnerability (CVE-2025-55182 class). The payload manipulates Object.prototype to achieve arbitrary code execution within the Node.js server process. FrontDoorAccessLog records the anomalous POST request to /_next/rsc with an oversized JSON body. AppServiceHTTPLogs capture the 200 response |
| 2 | Persistence | `T1505.003` | Server Software Component: Web Shell | Key log evidence: - FrontDoorAccessLog: HttpMethod=POST, RequestUri=/_next/rsc, ClientIp=attacker, RequestBytes>5000, HttpStatusCode=200 - FrontDoorWAFLog: Action=Allow (WAF in Detection mode failed to block) - AppServiceHTTPLogs: CsUriStem=/_next/rsc, CsMethod=POST, ScStatus=200, anomalous CsBytes |
| 3 | Credential Access | `T1552.005` | Unsecured Credentials: Cloud Instance Metadata API | ## Phase 2: Persistence (T1505.003) With RCE achieved, the attacker deploys a file-based web shell to the App Service filesystem. The web shell is written to a path under /home/site/wwwroot/ disguised as a legitimate application file (e.g., api/diagnostics.js). This provides persistent command execution access that survives application restarts. Subsequent requests to the web shell endpoint appear in AppServiceHTTPLogs with distinctive patterns — POST requests to the new endpoint with command parameters. |
| 4 | Discovery | `T1580` | Cloud Infrastructure Discovery | Key log evidence: - AppServiceHTTPLogs: CsUriStem=/api/diagnostics, CsMethod=POST, ScStatus=200, repeated from same CIp - AppServiceConsoleLogs: File write operations to /home/site/wwwroot/api/diagnostics.js |
| 5 | Collection | `T1530` | Data from Cloud Storage Object | ## Phase 3: Credential Access (T1552.005) Through the web shell, the attacker queries the Azure Instance Metadata Service (IMDS) at http://169.254.169.254/metadata/identity/oauth2/token with the Metadata:true header and resource=https://management.azure.com/. The IMDS endpoint returns a managed identity OAuth2 bearer token. A second token request targets resource=https://storage.azure.com/ for direct storage access. AzureIMDSAccessLogs record both token requests. |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1016` | Vulnerability Scanning | T1190 (Exploit Public-Facing Application) | Continuously scan public surfaces and validate fixes. |
| `M1018` | User Account Management | T1580 (Cloud Infrastructure Discovery), T1530 (Data from Cloud Storage Object) | Deny ListKeys at the policy level; require RBAC + just-in-time elevation. |
| `M1026` | Privileged Account Management | T1552.005 (Unsecured Credentials: Cloud Instance Metadata API) | Scope Managed Identities to least privilege so a stolen IMDS token has minimal blast radius. |
| `M1030` | Network Segmentation | T1190 (Exploit Public-Facing Application) | Isolate exposed workloads from sensitive backends; use private endpoints. |
| `M1037` | Filter Network Traffic | T1552.005 (Unsecured Credentials: Cloud Instance Metadata API), T1530 (Data from Cloud Storage Object) | Use NetworkPolicies / egress filtering to prevent untrusted workloads from reaching the metadata endpoint. |
| `M1041` | Encrypt Sensitive Information | T1530 (Data from Cloud Storage Object) | Encrypt blobs/objects at rest with customer-managed keys; require HTTPS and signed identities. |
| `M1042` | Disable or Remove Feature or Program | T1552.005 (Unsecured Credentials: Cloud Instance Metadata API) | Restrict pod / VM access to IMDS (block 169.254.169.254 except trusted callers); use IMDSv2-equivalent controls. |
| `M1047` | Audit | T1580 (Cloud Infrastructure Discovery) | Alert on high-volume ARM enumeration (listKeys, listResources) by non-automation principals. |
| `M1050` | Exploit Protection | T1190 (Exploit Public-Facing Application) | Enable WAF / RASP and runtime protections for exposed application endpoints. |
| `M1051` | Update Software | T1190 (Exploit Public-Facing Application) | Patch internet-facing applications promptly; track CVEs against deployed versions. |
| `AZ-COMPUTE-001` | Block pod / workload SSRF to IMDS | imds_ssrf | Apply egress NetworkPolicies (or AKS pod-managed-identity v2) so only system pods can reach 169.254.169.254. |
| `AZ-STORAGE-001` | Disable anonymous blob access | public_blob_container | Set storage account 'allowBlobPublicAccess=false' and audit any container with public-read; prefer SAS or Entra ID. |
