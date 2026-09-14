# Recon Agent Report — incident_34_v5

**Password Spray → SP Credential Injection → ARM Hub → Global Admin + Blob Exfil**

Multi-stage cloud attack where a threat actor compromises an Application Administrator
account via password spray against Azure AD, then injects new client credentials into a
high-privilege service principal (T1098.001). The attacker authenticates as the service
principal to pivot through Azure Resource Manager, which serves as the central hub in a
hub-and-spoke attack topology. From the ARM hub, the attacker branches to create a
persistent backdoor Global Administrator account and stages sensitive data from blob
storage containers for exfiltration. Variant 5 emphasizes explicit lateral movement
through ARM using SP credentials, creating a hub-and-spoke topology rather than a
linear credential chain.

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
| Service Principal Secret | `SP_CLIENT_SECRET` | `azure-ad` | Seeded uuid secret planted into the cyber range. Grants access to: azure-ad. **Weakened**: The attacker then calls the addPassword endpoint (T1098.001) on the target service principal, injecting a new client secret (SP_CLIENT_SECRET) without alerting the SP owner. |
| Credential (password) | `GLOBAL_ADMIN_CREDS` | `azure-ad` | Seeded password planted into the cyber range. Grants access to: azure-ad. **Weakened**: From the ARM hub, the attacker executes two parallel branches: Branch 1 — Persistence: The attacker uses the ARM_ACCESS_TOKEN to call Microsoft Graph and create a new Global Administrator account (T1136.003) with attacker-controlled credentials (GLOBAL_ADMIN_CREDS), establishing persistent backdoor access that survives SP credential rotation. |
| Service Principal (seeded) | `Subscription Contributor SP` | `Tenant` | Seeded SP `sp-contributor-app-id` with scopes/permissions:  |
| Blob Container | `financial-reports` | `proddata001` | Private container. **Weakened**: Branch 2 — Collection: The attacker uses the ARM_ACCESS_TOKEN to enumerate storage accounts via ARM, retrieves storage account access keys via the listKeys API, then accesses the target blob storage container (financial-reports) to stage and exfiltrate sensitive financial data (T1530). |
| Blob | `Q4-2025-revenue-summary.xlsx` | `financial-reports` | Seeded blob. |
| Blob | `customer-accounts-export.csv` | `financial-reports` | Seeded blob. |
| Blob | `payment-processing-config.json` | `financial-reports` | Seeded blob. |

## Expected Attack Path

**Kill chain:** Initial Access → Persistence → Lateral Movement → Persistence → Collection

**Entry point:** Password spray against Azure AD Application Administrator account

**Final objective:** Stage and exfiltrate sensitive data from Azure Blob Storage containers


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1110.003` | Brute Force: Password Spraying | A threat actor identifies an Azure AD tenant with an Application Administrator account that lacks multi-factor authentication enforcement. The attacker conducts a low-and-slow password spray campaign (T1110.003) against the tenant's OAuth2 token endpoint, testing common passwords across multiple accounts while staying below lockout thresholds. After successfully authenticating as the Application Administrator, the attacker obtains an OAuth access token (APP_ADMIN_TOKEN) with permissions to manage application registrations and service principals. |
| 2 | Persistence | `T1098.001` | Account Manipulation: Additional Cloud Credentials | Using the Application Administrator privileges, the attacker enumerates service principals via the Microsoft Graph API (/v1.0/servicePrincipals) to identify a high-privilege SP with Contributor role at subscription scope. The attacker then calls the addPassword endpoint (T1098.001) on the target service principal, injecting a new client secret (SP_CLIENT_SECRET) without alerting the SP owner. |
| 3 | Lateral Movement | `T1078.004` | Valid Accounts: Cloud Accounts | With the SP_CLIENT_SECRET, the attacker authenticates as the service principal using the OAuth2 client_credentials grant flow, obtaining an ARM-scoped access token (ARM_ACCESS_TOKEN). This token grants access to Azure Resource Manager, which becomes the central hub of the attack topology (T1078.004). |
| 4 | Persistence | `T1136.003` | Create Account: Cloud Account | From the ARM hub, the attacker executes two parallel branches: |
| 5 | Collection | `T1530` | Data from Cloud Storage Object | Branch 1 — Persistence: The attacker uses the ARM_ACCESS_TOKEN to call Microsoft Graph and create a new Global Administrator account (T1136.003) with attacker-controlled credentials (GLOBAL_ADMIN_CREDS), establishing persistent backdoor access that survives SP credential rotation. |

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
