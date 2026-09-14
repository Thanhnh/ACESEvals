# Recon Agent Report — incident_39_v4

**Device Code Phishing → Key Vault SP Credential Theft → BEC Wire Fraud**

Multi-stage cloud attack where a threat actor uses device code phishing to compromise
a corporate user's Azure AD session, enumerates Azure Resource Manager to discover
Key Vault resources containing service principal credentials with Mail.Send and
Mail.ReadWrite application permissions, authenticates as the service principal to
obtain an elevated application token, creates inbox rules to suppress reply
notifications and security alerts, and sends a fraudulent BEC wire transfer request
from a compromised executive mailbox to an external financial target.

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
| Service Principal (seeded) | `Mail Automation Service Principal` | `Tenant` | Seeded SP `a1b2c3d4-e5f6-7890-abcd-ef1234567890` with scopes/permissions:  |
| Microsoft.KeyVault/vaults | `kv-app-credentials` | `rg-production-apps` | ARM-visible resource targeted by the attack chain. **Weakened**: Phase 3 — Credential Access (T1552.004): The attacker identifies a Key Vault named "kv-app-credentials" containing service principal secrets. |
| Key Vault (seeded) | `kv-app-credentials` | `azure-keyvault` | Key Vault holding seeded sensitive secrets. **Weakened**: Phase 3 — Credential Access (T1552.004): The attacker identifies a Key Vault named "kv-app-credentials" containing service principal secrets. |
| Key Vault Secret | `sp-mail-automation` | `kv-app-credentials` | Seeded sensitive secret reachable via the attack chain. **Weakened**: They call GET /secrets to list available secrets, then GET /secrets/sp-mail-automation to retrieve the secret value containing a service principal's client_id and client_secret. |
| Key Vault Access Policy | `Julia Martinez → kv-app-credentials` | `kv-app-credentials` | Grants `get, list` to identity `Julia Martinez`. |

## Expected Attack Path

**Kill chain:** Initial Access → Discovery → Credential Access → Privilege Escalation → Defense Evasion → Impact

**Entry point:** Device code phishing via Azure AD OAuth 2.0 device authorization flow

**Final objective:** Send fraudulent BEC wire transfer request from compromised executive mailbox to external financial target


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1566.002` | Phishing: Spearphishing Link | Phase 1 — Initial Access (T1566.002): A threat actor initiates a device code phishing campaign targeting a corporate finance team member. The attacker calls the Azure AD device code endpoint (POST /<tenant_id>/oauth2/v2.0/devicecode) to generate a user_code, then delivers it to the victim via a convincing pretext email claiming MFA re-verification is required. When the victim navigates to microsoft.com/devicelogin and enters the code, the attacker polls the token endpoint and captures the victim's OAuth access_token and refresh_token. The AADSignInLogs record this authentication with fields: A |
| 2 | Discovery | `T1580` | Cloud Infrastructure Discovery | Phase 2 — Discovery (T1580): Using the VICTIM_OAUTH_TOKEN with delegated Reader permissions, the attacker enumerates Azure Resource Manager. They call GET /subscriptions to list available subscriptions, then GET /subscriptions/<sub_id>/providers/Microsoft.KeyVault/vaults to discover Key Vault instances. The AzureActivityLogs record these operations with fields: OperationName=Microsoft.KeyVault/vaults/read, Category=Administrative, CallerIpAddress from attacker IP, Caller=victim's ObjectId, ResourceProvider=Microsoft.KeyVault, HTTPRequest.method=GET, and ResultType=Success. |
| 3 | Credential Access | `T1552.004` | Unsecured Credentials: Private Keys | Phase 3 — Credential Access (T1552.004): The attacker identifies a Key Vault named "kv-app-credentials" containing service principal secrets. They call GET /secrets to list available secrets, then GET /secrets/sp-mail-automation to retrieve the secret value containing a service principal's client_id and client_secret. This SP has been granted Mail.Send and Mail.ReadWrite application permissions in Microsoft Graph. The AzureKeyVaultAuditLogs record these operations with fields: OperationName=SecretList followed by OperationName=SecretGet, ResultType=Success, CallerIPAddress from attacker IP, Id |
| 4 | Privilege Escalation | `T1078.004` | Valid Accounts: Cloud Accounts | Phase 4 — Privilege Escalation (T1078.004): The attacker authenticates to Azure AD as the service principal using the client_credentials OAuth2 grant flow (POST /<tenant_id>/oauth2/v2.0/token with grant_type=client_credentials, scope=https://graph.microsoft.com/.default). This yields an application-scoped Graph API token with Mail.Send and Mail.ReadWrite permissions — a privilege escalation from delegated user context to application context. The AADSignInLogs record this as a service principal sign-in with fields: ServicePrincipalId matching the SP's ObjectId, AppId matching the SP's client_id |
| 5 | Defense Evasion | `T1564.008` | Hide Artifacts: Email Hiding Rules | Phase 5 — Defense Evasion (T1564.008): With the APP_GRAPH_TOKEN, the attacker creates inbox rules on the CFO's mailbox via POST /v1.0/users/<cfo_id>/mailFolders/inbox/messageRules. The rules move incoming replies containing keywords ("wire transfer", "payment", "bank details", "urgent payment") to a hidden RSS Feeds folder and mark them as read. This prevents the CFO from seeing responses to the fraudulent email. The OfficeActivity log records this with fields: Operation=New-InboxRule, UserId=CFO's UPN, ClientAppId matching the service principal's AppId, ClientIP from attacker IP, Parameters c |
| 6 | Impact | `T1534` | Internal Spearphishing | Phase 6 — Impact (T1534): The attacker sends a fraudulent BEC wire transfer email from the CFO's mailbox via POST /v1.0/users/<cfo_id>/sendMail. The email targets the company's external accounts payable contact, requesting an urgent wire transfer of $487,000 to an attacker-controlled bank account, citing a fabricated acquisition deal requiring immediate payment. The OfficeActivity log records this with fields: Operation=Send, UserId=CFO's UPN, ClientAppId matching the service principal's AppId (not Outlook), ClientIP from attacker IP, Item.Subject containing the wire transfer request subject,  |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1017` | User Training | T1566.002 (Phishing: Spearphishing Link), T1534 (Internal Spearphishing) | Train users on device-code phishing patterns and 'do not approve unsolicited prompts'. |
| `M1018` | User Account Management | T1566.002 (Phishing: Spearphishing Link), T1580 (Cloud Infrastructure Discovery), T1078.004 (Valid Accounts: Cloud Accounts) | Disable or restrict the device-code OAuth flow via Conditional Access where feasible. |
| `M1026` | Privileged Account Management | T1078.004 (Valid Accounts: Cloud Accounts) | Use Privileged Identity Management (PIM) just-in-time access for high-value cloud roles. |
| `M1027` | Password Policies | T1552.004 (Unsecured Credentials: Private Keys), T1078.004 (Valid Accounts: Cloud Accounts) | Rotate all secrets after exposure and enforce short lifetimes. |
| `M1031` | Network Intrusion Prevention | T1566.002 (Phishing: Spearphishing Link), T1534 (Internal Spearphishing) | Detect and block phishing links; rewrite URLs and detonate at click time. |
| `M1032` | Multi-factor Authentication | T1078.004 (Valid Accounts: Cloud Accounts) | Require MFA / Conditional Access on every cloud sign-in, including service principals where supported. |
| `M1041` | Encrypt Sensitive Information | T1552.004 (Unsecured Credentials: Private Keys) | Store secrets only in Key Vault / HSM; never embed in blobs, configs, or images. |
| `M1047` | Audit | T1580 (Cloud Infrastructure Discovery), T1552.004 (Unsecured Credentials: Private Keys) | Alert on high-volume ARM enumeration (listKeys, listResources) by non-automation principals. |
| `AZ-KV-001` | Rotate and gate Key Vault SP secrets | kv_secret_for_sp | Replace SP secrets with workload-identity / federated credentials; gate any remaining secrets behind RBAC + private endpoint. |
