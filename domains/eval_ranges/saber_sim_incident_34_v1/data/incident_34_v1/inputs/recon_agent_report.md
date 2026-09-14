# Recon Agent Report — incident_34_v1

**Compromised Azure AD Credentials → ARM Enumeration → SP addPassword → Backdoor Account → Blob Exfiltration**

A credential abuse attack in which a threat actor leverages compromised valid Azure AD
account credentials to authenticate and enumerate Azure Resource Manager resources.
The attacker discovers service principals with elevated permissions, injects additional
credentials via addPassword to escalate privileges, creates a persistent backdoor cloud
account, and stages sensitive data from Azure Blob Storage for exfiltration. This variant
uses ARM resource enumeration as the lateral movement path before pivoting to privilege
escalation and storage access.

_Generated: 2026-07-14T17:56:55+00:00_

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
| Service Principal Secret | `SP_CLIENT_SECRET` | `azure-ad, azure-blob-storage` | Seeded uuid secret planted into the cyber range. Grants access to: azure-ad, azure-blob-storage. |
| Service Principal (seeded) | `Data Pipeline Service Principal` | `Tenant` | Seeded SP `a1b2c3d4-e5f6-7890-abcd-ef1234567890` with scopes/permissions:  |
| Blob Container | `financial-reports` | `proddata001` | Private container. |
| Blob | `Q2-2026-revenue-forecast.xlsx` | `financial-reports` | Seeded blob. |
| Blob | `annual-budget-2026.pdf` | `financial-reports` | Seeded blob. |
| Blob Container | `hr-data` | `proddata001` | Private container. |
| Blob | `employee-records-export.csv` | `hr-data` | Seeded blob. |
| Blob Container | `engineering-ip` | `proddata001` | Private container. |
| Blob | `architecture-diagrams.zip` | `engineering-ip` | Seeded blob. |

## Expected Attack Path

**Kill chain:** Initial Access → Discovery → Discovery → Privilege Escalation → Persistence → Collection

**Entry point:** Compromised valid Azure AD account credentials

**Final objective:** Stage and exfiltrate sensitive data from Azure Blob Storage


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1078.004` | Valid Accounts: Cloud Accounts | A threat actor obtains compromised Azure AD credentials for a legitimate user account (e.g., via credential stuffing or dark web purchase). The attacker authenticates to Azure AD using these valid credentials, obtaining an OAuth access token (T1078.004 — Valid Accounts: Cloud Accounts). |
| 2 | Discovery | `T1580` | Cloud Infrastructure Discovery | With the user's token, the attacker enumerates Azure Resource Manager (ARM) resources by calling /subscriptions and /subscriptions/{id}/resourcegroups endpoints on the ARM API (T1580 — Cloud Infrastructure Discovery). This reveals the organization's resource topology including storage accounts, key vaults, and web apps. |
| 3 | Discovery | `T1087.004` | Account Discovery: Cloud Account | The attacker then queries the Microsoft Graph API endpoint /v1.0/servicePrincipals to discover service principals with elevated role assignments (T1087.004 — Account Discovery: Cloud Account). They identify a service principal with Owner or Contributor role on the subscription, which has permissions to access storage accounts and manage directory objects. |
| 4 | Privilege Escalation | `T1098.001` | Account Manipulation: Additional Cloud Credentials | Exploiting the compromised user's Application Administrator or equivalent directory role, the attacker calls /v1.0/servicePrincipals/{sp_id}/addPassword to inject a new client secret onto the discovered high-privilege service principal (T1098.001 — Account Manipulation: Additional Cloud Credentials). This grants the attacker a fresh credential for the elevated SP without alerting the SP owner. |
| 5 | Persistence | `T1136.003` | Create Account: Cloud Account | Using the newly minted SP client secret, the attacker authenticates as the service principal via the /oauth2/v2.0/token endpoint and creates a new Azure AD user account as a persistent backdoor (T1136.003 — Create Account: Cloud Account). This ensures continued access even if the original compromised credentials are rotated. |
| 6 | Collection | `T1530` | Data from Cloud Storage Object | Finally, the attacker uses the elevated service principal's storage permissions to access Azure Blob Storage, listing containers and downloading sensitive blobs — financial reports, HR data, or intellectual property (T1530 — Data from Cloud Storage Object). The data is staged for exfiltration to an external location. |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1018` | User Account Management | T1078.004 (Valid Accounts: Cloud Accounts), T1580 (Cloud Infrastructure Discovery), T1087.004 (Account Discovery: Cloud Account), T1530 (Data from Cloud Storage Object) | Audit cloud account roles, remove standing privileges, and disable unused service principals. |
| `M1026` | Privileged Account Management | T1078.004 (Valid Accounts: Cloud Accounts) | Use Privileged Identity Management (PIM) just-in-time access for high-value cloud roles. |
| `M1027` | Password Policies | T1078.004 (Valid Accounts: Cloud Accounts) | Enforce strong, rotated credentials and disable inactive / stale accounts. |
| `M1032` | Multi-factor Authentication | T1078.004 (Valid Accounts: Cloud Accounts) | Require MFA / Conditional Access on every cloud sign-in, including service principals where supported. |
| `M1037` | Filter Network Traffic | T1530 (Data from Cloud Storage Object) | Constrain storage account access to private endpoints / trusted networks. |
| `M1041` | Encrypt Sensitive Information | T1530 (Data from Cloud Storage Object) | Encrypt blobs/objects at rest with customer-managed keys; require HTTPS and signed identities. |
| `M1047` | Audit | T1580 (Cloud Infrastructure Discovery), T1087.004 (Account Discovery: Cloud Account) | Alert on high-volume ARM enumeration (listKeys, listResources) by non-automation principals. |
| `AZ-STORAGE-001` | Disable anonymous blob access | public_blob_container | Set storage account 'allowBlobPublicAccess=false' and audit any container with public-read; prefer SAS or Entra ID. |
