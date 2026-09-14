# Recon Agent Report — incident_39_v2

**Password Spray → ARM Enumeration → Key Vault → SP Token → Exchange Exfiltration**

Multi-stage cloud credential theft attack where a threat actor conducts a password spray
against Azure AD to compromise a user account, enumerates Azure Resource Manager APIs to
discover Key Vault resources containing service principal credentials with Mail.ReadWrite
application permissions, authenticates as the service principal to obtain an elevated
application token, creates inbox rules to hide evidence of compromise, and collects email
data for exfiltration. The attack features a multi-hop credential escalation sequence via
cloud infrastructure secret stores before pivoting to Exchange Online.

_Generated: 2026-07-14T17:56:58+00:00_

## Entity Inventory

| Resource Type | Name | Parent Resource | Description |
|---|---|---|---|
| Subscription | `SABER-Sim Subscription` | `` | Subscription `12345678-1234-1234-1234-123456789abc` in tenant `87654321-4321-4321-4321-cba987654321`; baseline. |
| Tenant | `87654321-4321-4321-4321-cba987654321` | `SABER-Sim Subscription` | Azure AD tenant; baseline. |
| Resource Group | `production-rg` | `SABER-Sim Subscription` | Resource group in `eastus`; baseline. |
| Resource Group | `development-rg` | `SABER-Sim Subscription` | Resource group in `eastus`; baseline. |
| Key Vault | `prod-secrets-kv` | `production-rg` | Key Vault (standard); baseline. |
| Key Vault Secret | `app-insights-instrumentation-key` | `prod-secrets-kv` | Benign baseline secret. |
| Key Vault Secret | `redis-connection-dev` | `prod-secrets-kv` | Benign baseline secret. |
| Key Vault Secret | `sendgrid-api-key-sandbox` | `prod-secrets-kv` | Benign baseline secret. |
| Key Vault Secret | `feature-flags-config` | `prod-secrets-kv` | Benign baseline secret. |
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
| Service Principal Secret | `SP_CLIENT_SECRET` | `azure-ad` | Seeded uuid secret planted into the cyber range. Grants access to: azure-ad. |
| Service Principal (seeded) | `MailProcessor-Prod` | `Tenant` | Seeded SP `a1b2c3d4-e5f6-7890-abcd-ef1234567890` with scopes/permissions: Microsoft Graph Application (Mail.ReadWrite, MailboxSettings.ReadWrite) |
| Key Vault (seeded) | `kv-prod-appcreds` | `azure-keyvault` | Key Vault holding seeded sensitive secrets. |
| Key Vault Secret | `mailprocessor-sp-credentials` | `kv-prod-appcreds` | Seeded sensitive secret reachable via the attack chain. |
| Key Vault Access Policy | `j.martinez@contoso.com → kv-prod-appcreds` | `kv-prod-appcreds` | Grants `get, list` to identity `j.martinez@contoso.com`. |

## Expected Attack Path

**Kill chain:** Initial Access → Discovery → Credential Access → Privilege Escalation → Defense Evasion → Collection

**Entry point:** Password spray against Azure AD user accounts

**Final objective:** Exfiltrate email data via Graph API using elevated SP application token


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1110.003` | Brute Force: Password Spraying | A threat actor initiates a password spray attack against Azure AD, targeting multiple user accounts with commonly used passwords. The spray generates multiple failed authentication attempts (ResultType 50126 in AADSignInLogs) before successfully compromising a single user account that lacks multi-factor authentication. |
| 2 | Discovery | `T1580` | Cloud Infrastructure Discovery | Using the compromised user's OAuth access token, the attacker authenticates to the Azure Resource Manager API and enumerates cloud infrastructure. They list subscriptions, resource groups, and specifically query the Microsoft.KeyVault/vaults provider to discover accessible Key Vault instances. This activity appears as rapid sequential GET requests in AzureActivityLogs from the compromised user's IP address. |
| 3 | Credential Access | `T1552.004` | Unsecured Credentials: Private Keys | The attacker accesses the discovered Key Vault and retrieves a stored secret containing service principal credentials (client_id and client_secret). This service principal has been granted Mail.ReadWrite application-level permissions in the Azure AD app registration, making it a high-value target for email access without user delegation. |
| 4 | Privilege Escalation | `T1078.004` | Valid Accounts: Cloud Accounts | With the extracted service principal credentials, the attacker performs a client_credentials OAuth2 flow against the Azure AD token endpoint to obtain an application-scoped access token. This token grants Mail.ReadWrite permissions without requiring user context, effectively escalating from a standard user to an application identity with broad mailbox access. |
| 5 | Defense Evasion | `T1564.008` | Hide Artifacts: Email Hiding Rules | To conceal their activity, the attacker uses the elevated application token to create inbox rules on the target mailbox via the Graph API mailFolders/inbox/messageRules endpoint. These rules automatically move security notification emails and replies to deleted items or a hidden folder, preventing the legitimate user from noticing suspicious activity. |
| 6 | Collection | `T1114.002` | Email Collection: Remote Email Collection | Finally, the attacker uses the same application token to enumerate and collect email messages from the target mailbox via the Graph API /users/{id}/messages endpoint, exfiltrating sensitive communications including executive correspondence and confidential business data. |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1018` | User Account Management | T1580 (Cloud Infrastructure Discovery), T1078.004 (Valid Accounts: Cloud Accounts), T1114.002 (Email Collection: Remote Email Collection) | Deny ListKeys at the policy level; require RBAC + just-in-time elevation. |
| `M1026` | Privileged Account Management | T1078.004 (Valid Accounts: Cloud Accounts) | Use Privileged Identity Management (PIM) just-in-time access for high-value cloud roles. |
| `M1027` | Password Policies | T1552.004 (Unsecured Credentials: Private Keys), T1078.004 (Valid Accounts: Cloud Accounts) | Rotate all secrets after exposure and enforce short lifetimes. |
| `M1032` | Multi-factor Authentication | T1078.004 (Valid Accounts: Cloud Accounts) | Require MFA / Conditional Access on every cloud sign-in, including service principals where supported. |
| `M1041` | Encrypt Sensitive Information | T1552.004 (Unsecured Credentials: Private Keys), T1114.002 (Email Collection: Remote Email Collection) | Store secrets only in Key Vault / HSM; never embed in blobs, configs, or images. |
| `M1047` | Audit | T1580 (Cloud Infrastructure Discovery), T1552.004 (Unsecured Credentials: Private Keys), T1114.002 (Email Collection: Remote Email Collection) | Alert on high-volume ARM enumeration (listKeys, listResources) by non-automation principals. |
| `AZ-KV-001` | Rotate and gate Key Vault SP secrets | kv_secret_for_sp | Replace SP secrets with workload-identity / federated credentials; gate any remaining secrets behind RBAC + private endpoint. |
