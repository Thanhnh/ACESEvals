# Recon Agent Report — incident_34_v3

**Compromised Azure AD Creds → ARM Pivot → SP Credential Addition → Backdoor Account → Blob Exfiltration**

Multi-stage credential abuse attack in which a threat actor authenticates
with compromised Azure AD credentials, pivots through the ARM management
plane to add credentials to a high-privilege service principal, re-enters
Azure AD with elevated SP credentials to create a persistent backdoor cloud
account, then laterally moves to blob storage under the backdoor identity
to stage and exfiltrate sensitive data. Variant 3 emphasizes the ARM lateral
movement path and backdoor identity pivot to blob storage.

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
| Service Principal Secret | `SP_CLIENT_SECRET` | `azure-ad` | Seeded uuid secret planted into the cyber range. Grants access to: azure-ad. |
| Service Principal (seeded) | `graph-automation-sp` | `Tenant` | Seeded SP `a1b2c3d4-e5f6-7890-abcd-ef1234567890` with scopes/permissions:  |
| Blob Container | `financial-reports` | `proddata001` | Private container. |
| Blob | `Q2-2026-revenue-forecast.xlsx` | `financial-reports` | Seeded blob. |
| Blob | `customer-pii-export-20260601.csv` | `financial-reports` | Seeded blob. |
| Blob Container | `db-backups` | `proddata001` | Private container. |
| Blob | `prod-sqldb-20260602.bak` | `db-backups` | Seeded blob. |

## Expected Attack Path

**Kill chain:** Initial Access → Privilege Escalation → Lateral Movement → Persistence → Lateral Movement → Collection

**Entry point:** Compromised Azure AD user credentials (valid account)

**Final objective:** Stage and exfiltrate sensitive data from Azure Blob Storage via backdoor identity


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1078.004` | Valid Accounts: Cloud Accounts | A threat actor obtains compromised Azure AD credentials for a legitimate user account through prior credential theft. In variant 3, the attacker follows a distinct lateral movement path through the ARM management plane: |
| 2 | Privilege Escalation | `T1098.001` | Account Manipulation: Additional Cloud Credentials | 1. INITIAL ACCESS (T1078.004): The attacker authenticates to Azure AD using the    compromised user credentials, obtaining an OAuth token with Contributor-level    access to the Azure Resource Manager plane. Evidence appears in AADSignInLogs    as a sign-in event (sign_in_log) showing authentication from an anomalous IP    address with resource scope https://management.azure.com. |
| 3 | Lateral Movement | `T1078.004` | Valid Accounts: Cloud Accounts | 2. PRIVILEGE ESCALATION (T1098.001): Using the ARM access token, the attacker    enumerates service principals via the ARM management plane and identifies one    with Directory.ReadWrite.All permissions. The attacker calls addPassword on    this high-privilege service principal, adding a new client secret they control.    This operation generates an entry in AzureActivityLogs (azure_activity_log /    activity_log) with operationName "Add service principal credentials" and the    caller's objectId. |
| 4 | Persistence | `T1136.003` | Create Account: Cloud Account | 3. LATERAL MOVEMENT (T1078.004): The attacker re-authenticates to Azure AD using    the newly minted SP client secret, performing the OAuth2 client_credentials    flow. This represents lateral movement from the user identity context through    the ARM plane into a new SP identity with elevated directory permissions.    A new sign-in event appears in AADSignInLogs (sign_in_log) with    servicePrincipalId and appId fields identifying the compromised SP, and    authenticationMethod "client_secret". |
| 5 | Lateral Movement | `T1078.004` | Valid Accounts: Cloud Accounts | 4. PERSISTENCE (T1136.003): With the elevated SP access token, the attacker    creates a new backdoor cloud account (user) in the Azure AD tenant via Graph    API. The account is given an innocuous display name mimicking a service    account (e.g., "svc-backup-sync") and granted the Storage Blob Data    Contributor role assignment on the target storage account. This operation    is logged in AzureActivityLogs (azure_activity_log) with operationName    "Create user" and a role assignment creation event. |
| 6 | Collection | `T1530` | Data from Cloud Storage Object | 5. LATERAL MOVEMENT (T1078.004): The attacker signs in as the newly created    backdoor account, pivoting away from both the original compromised identity    and the SP identity. The new authentication appears in AADSignInLogs    (sign_in_log) as a first-time sign-in for a newly created account, with    resource scope https://storage.azure.com. This lateral pivot makes    attribution more difficult. |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1018` | User Account Management | T1078.004 (Valid Accounts: Cloud Accounts), T1530 (Data from Cloud Storage Object) | Audit cloud account roles, remove standing privileges, and disable unused service principals. |
| `M1026` | Privileged Account Management | T1078.004 (Valid Accounts: Cloud Accounts) | Use Privileged Identity Management (PIM) just-in-time access for high-value cloud roles. |
| `M1027` | Password Policies | T1078.004 (Valid Accounts: Cloud Accounts) | Enforce strong, rotated credentials and disable inactive / stale accounts. |
| `M1032` | Multi-factor Authentication | T1078.004 (Valid Accounts: Cloud Accounts) | Require MFA / Conditional Access on every cloud sign-in, including service principals where supported. |
| `M1037` | Filter Network Traffic | T1530 (Data from Cloud Storage Object) | Constrain storage account access to private endpoints / trusted networks. |
| `M1041` | Encrypt Sensitive Information | T1530 (Data from Cloud Storage Object) | Encrypt blobs/objects at rest with customer-managed keys; require HTTPS and signed identities. |
| `AZ-STORAGE-001` | Disable anonymous blob access | public_blob_container | Set storage account 'allowBlobPublicAccess=false' and audit any container with public-read; prefer SAS or Entra ID. |
