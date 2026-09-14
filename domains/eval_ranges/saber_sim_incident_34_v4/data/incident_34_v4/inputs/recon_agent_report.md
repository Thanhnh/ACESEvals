# Recon Agent Report — incident_34_v4

**Compromised Account → ARM Pivot → SP Credential Injection → Backdoor Admin → Blob Exfiltration**

Credential abuse attack where a threat actor leverages compromised valid cloud accounts
to escalate privileges in Azure AD by injecting credentials into an existing service
principal via the ARM API, creates persistent backdoor administrator accounts for
long-term access, then laterally moves through ARM to Azure Blob Storage to stage
sensitive data for exfiltration. Variant 4 differentiates from prior variants by
pivoting through ARM API for privilege escalation before establishing persistence,
then using the backdoor identity as the lateral movement vehicle to reach storage
resources.

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
| SAS Token | `STORAGE_SAS_TOKEN` | `azure-blob-storage` | Seeded sas token planted into the cyber range. Grants access to: azure-blob-storage. |
| Service Principal (seeded) | `InfraAutomation-Prod` | `Tenant` | Seeded SP `infra-automation-app-id` with scopes/permissions:  |
| Blob Container | `financial-records` | `proddata001` | Private container. 1 SAS token(s) seeded against this container. |
| Blob | `q4-revenue-forecast.xlsx` | `financial-records` | Seeded blob. |
| Blob | `payroll-2026.csv` | `financial-records` | Seeded blob. |
| Blob Container | `ip-documents` | `proddata001` | Private container. 1 SAS token(s) seeded against this container. |
| Blob | `product-roadmap-internal.pdf` | `ip-documents` | Seeded blob. |
| Blob Container | `exfil-staging` | `proddata001` | Private container. 1 SAS token(s) seeded against this container. |
| IMDS-Exposed Token | `managed_identity` | `169.254.169.254` | Managed Identity token reachable via IMDS — exploitable via SSRF. |

## Expected Attack Path

**Kill chain:** Initial Access → Privilege Escalation → Persistence → Lateral Movement → Collection

**Entry point:** Compromised valid Azure AD account credentials

**Final objective:** Exfiltrate sensitive data from Azure Blob Storage via backdoor admin


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1078.004` | Valid Accounts: Cloud Accounts | A threat actor possessing previously compromised Azure AD credentials authenticates to Azure using valid cloud accounts (T1078.004). The sign-in targets the ARM management plane — visible in AADSignInLogs with ResourceDisplayName "Windows Azure Service Management API", ResultType "0" (success), AuthenticationRequirement "singleFactorAuthentication" indicating the account lacks MFA enforcement, ConditionalAccessStatus "success", IsInteractive true, UserType "Member", and TokenIssuerType "AzureAD". The IPAddress and Location fields record the attacker's origin. The CorrelationId links this sign- |
| 2 | Privilege Escalation | `T1098.001` | Account Manipulation: Additional Cloud Credentials | Using the ARM access token, the attacker escalates privileges by injecting a new client secret into an existing high-privilege service principal via the addPassword API (T1098.001). AzureActivityLogs records this with operationName "Microsoft.Directory/servicePrincipals/credentials/update", category "Administrative", resultType "Success", resultSignature "Succeeded", level "Informational". The identity object contains the compromised user's claims (oid, appid) and authorization evidence showing "Application Administrator" role. The callerIpAddress, correlationId, and resourceId provide attribu |
| 3 | Persistence | `T1136.003` | Create Account: Cloud Account | The attacker authenticates as the service principal and creates a backdoor Global Administrator account named "svc-backup-sync" (T1136.003). AADSignInLogs shows the SP authentication with IsInteractive false, ResultType "0", ResourceDisplayName "Microsoft Graph", RiskLevelDuringSignIn "none", TokenIssuerType "AzureAD", ClientAppUsed showing the SDK client, and AppDisplayName/AppId identifying the SP. The account creation generates an AzureActivityLogs entry with operationName "Microsoft.Authorization/roleAssignments/write", category "Administrative", resultType "Success", callerIpAddress from  |
| 4 | Lateral Movement | `T1580` | Cloud Infrastructure Discovery | The backdoor admin authenticates and uses ARM to discover and access storage resources (T1580). AADSignInLogs records the sign-in with UserPrincipalName "svc-backup-sync@contoso.onmicrosoft.com", ResourceDisplayName "Windows Azure Service Management API", RiskLevelDuringSignIn "none" (new account has no risk baseline), RiskLevelAggregated "none", AuthenticationRequirement "singleFactorAuthentication", and UserDisplayName showing the service account convention. AzureActivityLogs records the listKeys operation with operationName "Microsoft.Storage/storageAccounts/listKeys/action", category "Admi |
| 5 | Collection | `T1530` | Data from Cloud Storage Object | Finally, the attacker uses the storage account key to bulk-download sensitive data (T1530). StorageBlobLogs captures each access with operationName "GetBlob" (and "ListBlobs" for enumeration), category "StorageRead", statusCode 200, statusText "Success", identity.type "AccountKey", identity.tokenHash tracking the specific key, callerIpAddress from the attacker (with port), uri showing the exact blob path (e.g. finance/quarterly-reports.xlsx), protocol "HTTPS", correlationId, resourceId, durationMs, and properties containing accountName, userAgentHeader ("azsdk-python-storage-blob/12.19.0"), ob |

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
| `AZ-COMPUTE-001` | Block pod / workload SSRF to IMDS | imds_ssrf | Apply egress NetworkPolicies (or AKS pod-managed-identity v2) so only system pods can reach 169.254.169.254. |
| `AZ-STORAGE-001` | Disable anonymous blob access | public_blob_container | Set storage account 'allowBlobPublicAccess=false' and audit any container with public-read; prefer SAS or Entra ID. |
| `AZ-STORAGE-002` | Eliminate long-lived SAS tokens | leaked_sas_token | Replace static SAS with short-lived user-delegation SAS, scope to least privilege, and scan blobs/repos for leaked tokens. |
