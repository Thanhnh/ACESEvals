# Recon Agent Report — incident_34_v2

**Valid Cloud Credentials → SP Backdoor → Backdoor Account → ARM Pivot → Blob Exfiltration**

Multi-stage Azure AD credential abuse attack. A threat actor authenticates using
compromised valid cloud account credentials (T1078.004), then escalates privileges
by adding backdoor credentials to a service principal (T1098.001). The attacker
establishes persistence by creating a backdoor cloud account (T1136.003), uses the
backdoor identity to enumerate ARM resources discovering storage accounts (T1580),
and ultimately exfiltrates sensitive data from blob storage (T1530). Variant 2 uses
ARM enumeration as the lateral movement pivot before accessing storage through the
backdoor identity.

_Generated: 2026-07-14T17:56:54+00:00_

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
| Service Principal Secret | `SP_CLIENT_SECRET` | `azure-ad` | Seeded uuid secret planted into the cyber range. Grants access to: azure-ad. **Weakened**: The attacker now possesses SP_CLIENT_SECRET — an independent authentication credential for the elevated service principal. |
| Service Principal (seeded) | `ProdApp-ServicePrincipal` | `Tenant` | Seeded SP `a1b2c3d4-e5f6-7890-abcd-ef1234567890` with scopes/permissions:  |
| Blob Container | `financial-reports` | `proddata001` | Private container. |
| Blob | `Q4-2025-revenue-forecast.xlsx` | `financial-reports` | Seeded blob. |
| Blob | `customer-pii-export.csv` | `financial-reports` | Seeded blob. |
| Blob | `merger-acquisition-terms.pdf` | `financial-reports` | Seeded blob. |
| Blob Container | `backups` | `proddata001` | Private container. |
| Blob | `db-dump-20260501.sql.gz` | `backups` | Seeded blob. |

## Expected Attack Path

**Kill chain:** Initial Access → Privilege Escalation → Persistence → Discovery → Collection

**Entry point:** Compromised valid cloud account credentials used to authenticate to Azure AD

**Final objective:** Exfiltrate sensitive data from Azure Blob Storage via backdoor identity


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1078.004` | Valid Accounts: Cloud Accounts | A threat actor possessing previously compromised Azure AD credentials authenticates to the target tenant using valid cloud account access (T1078.004). The sign-in originates from an anomalous IP address and generates entries in AADSignInLogs with ResultType 0 (success), an unusual Location field, and a non-compliant DeviceDetail. The UserPrincipalName matches a legitimate employee but the IPAddress and ClientAppUsed fields indicate unauthorized access. |
| 2 | Privilege Escalation | `T1098.001` | Account Manipulation: Additional Cloud Credentials | Once authenticated with the USER_OAUTH_TOKEN, the attacker escalates privileges by calling the Microsoft Graph API endpoint /v1.0/servicePrincipals/{sp_id}/addPassword to inject a new client secret onto a discovered high-privilege service principal (T1098.001). This operation is recorded in AADSignInLogs with the OperationName "Add service principal credentials" and the target ServicePrincipalId. The attacker now possesses SP_CLIENT_SECRET — an independent authentication credential for the elevated service principal. |
| 3 | Persistence | `T1136.003` | Create Account: Cloud Account | Using the SP_CLIENT_SECRET, the attacker authenticates as the service principal via POST /{tenant_id}/oauth2/v2.0/token with grant_type=client_credentials, then calls the Microsoft Graph API to create a new Azure AD user account (T1136.003). The backdoor account is assigned Storage Blob Data Contributor role on the target subscription. This creation event appears in AADSignInLogs with the SP as the caller and generates an AzureActivityLogs entry for the role assignment. The attacker immediately authenticates as the backdoor account to obtain BACKDOOR_OAUTH_TOKEN. |
| 4 | Discovery | `T1580` | Cloud Infrastructure Discovery | With the BACKDOOR_OAUTH_TOKEN, the attacker enumerates Azure Resource Manager resources (T1580) by calling GET /subscriptions, GET /subscriptions/{sub_id}/resourcegroups, and GET /subscriptions/{sub_id}/providers/Microsoft.Storage/storageAccounts. These ARM enumeration calls are logged in AzureActivityLogs with the backdoor account's Caller identity, revealing rapid sequential List operations across resource providers. The attacker identifies storage accounts containing sensitive data via the ARM response (gaining STORAGE_ACCOUNT_ID). |
| 5 | Collection | `T1530` | Data from Cloud Storage Object | Finally, using the same BACKDOOR_OAUTH_TOKEN with Storage Blob Data Contributor permissions, the attacker directly accesses Azure Blob Storage (T1530). The attacker calls ListBlobs on target containers and GetBlob on individual sensitive objects (financial reports, customer PII, intellectual property). These operations are recorded in StorageBlobLogs with the RequesterObjectId matching the backdoor account, OperationName of GetBlob/ListBlobs, and the target ContainerName and ObjectKey fields identifying the exfiltrated data. |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1018` | User Account Management | T1078.004 (Valid Accounts: Cloud Accounts), T1580 (Cloud Infrastructure Discovery), T1530 (Data from Cloud Storage Object) | Audit cloud account roles, remove standing privileges, and disable unused service principals. |
| `M1026` | Privileged Account Management | T1078.004 (Valid Accounts: Cloud Accounts) | Use Privileged Identity Management (PIM) just-in-time access for high-value cloud roles. |
| `M1027` | Password Policies | T1078.004 (Valid Accounts: Cloud Accounts) | Enforce strong, rotated credentials and disable inactive / stale accounts. |
| `M1032` | Multi-factor Authentication | T1078.004 (Valid Accounts: Cloud Accounts) | Require MFA / Conditional Access on every cloud sign-in, including service principals where supported. |
| `M1037` | Filter Network Traffic | T1530 (Data from Cloud Storage Object) | Constrain storage account access to private endpoints / trusted networks. |
| `M1041` | Encrypt Sensitive Information | T1530 (Data from Cloud Storage Object) | Encrypt blobs/objects at rest with customer-managed keys; require HTTPS and signed identities. |
| `M1047` | Audit | T1580 (Cloud Infrastructure Discovery) | Alert on high-volume ARM enumeration (listKeys, listResources) by non-automation principals. |
| `AZ-STORAGE-001` | Disable anonymous blob access | public_blob_container | Set storage account 'allowBlobPublicAccess=false' and audit any container with public-read; prefer SAS or Entra ID. |
