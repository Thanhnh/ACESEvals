# Recon Agent Report — incident_134_v3

**OAuth App Consent Phishing → Mailbox Reconnaissance → Inbox Rule Evasion → BEC Wire Fraud**

Business Email Compromise wire fraud attack leveraging OAuth application consent
phishing as the initial access vector. The attacker registers a malicious Azure AD
application requesting Mail.ReadWrite and Mail.Send delegated permissions, then
tricks a corporate executive (CFO) into granting OAuth consent via a spearphishing
link disguised as a document sharing notification. Once consent is granted, the
attacker authenticates as the victim using delegated permissions, reads mailbox
contents to identify high-value financial contacts and pending wire transfers,
creates inbox rules to suppress reply notifications from targeted recipients, and
sends fraudulent wire transfer requests impersonating the compromised executive.
This is variant 3, using app consent phishing as the differentiated initial access
vector.

_Generated: 2026-07-14T17:56:56+00:00_

## Entity Inventory

| Resource Type | Name | Parent Resource | Description |
|---|---|---|---|
| Subscription | `SABER-Sim Subscription` | `` | Subscription `12345678-1234-1234-1234-123456789abc` in tenant `87654321-4321-4321-4321-cba987654321`; baseline. |
| Tenant | `87654321-4321-4321-4321-cba987654321` | `SABER-Sim Subscription` | Azure AD tenant; baseline. |
| Resource Group | `production-rg` | `SABER-Sim Subscription` | Resource group in `eastus`; baseline. |
| Resource Group | `development-rg` | `SABER-Sim Subscription` | Resource group in `eastus`; baseline. |
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

## Expected Attack Path

**Kill chain:** Initial Access → Credential Access → Collection → Defense Evasion → Impact

**Entry point:** OAuth application consent phishing via spearphishing link

**Final objective:** BEC wire fraud — fraudulent wire transfer request sent to finance team impersonating CFO


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1566.002` | Phishing: Spearphishing Link | ## Phase 1: Initial Access — OAuth App Consent Phishing (T1566.002) |
| 2 | Credential Access | `T1078.004` | Valid Accounts: Cloud Accounts | The threat actor registers a malicious Azure AD application named "DocuShare Secure Viewer" in an attacker-controlled tenant, configured to request delegated permissions for Mail.ReadWrite and Mail.Send. The attacker crafts a spearphishing email to the CFO (cfo@contoso.com) appearing to be a document sharing notification from a known business partner. The email contains a link to the Azure AD OAuth consent page (login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize) with the malicious app's client_id and the requested scopes. |
| 3 | Collection | `T1114.002` | Email Collection: Remote Email Collection | **Log Evidence (AADSignInLogs):** An interactive sign-in event for the CFO with AppDisplayName="DocuShare Secure Viewer", ConsentProvidedForScopes including "Mail.ReadWrite Mail.Send", and ResultType=0 (success). The IPAddress shows the victim's corporate IP as they click the consent link. |
| 4 | Defense Evasion | `T1564.008` | Hide Artifacts: Email Hiding Rules | ## Phase 2: Credential Access — Delegated Token Acquisition (T1078.004) |
| 5 | Impact | `T1534` | Internal Spearphishing | After the victim grants consent, the malicious application receives an authorization code which it exchanges at the Azure AD token endpoint (/{tenant}/oauth2/v2.0/token) for a delegated access token. This token has Mail.ReadWrite and Mail.Send scopes and is issued on behalf of the CFO. The attacker now authenticates as the victim from their own infrastructure. |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1017` | User Training | T1566.002 (Phishing: Spearphishing Link), T1534 (Internal Spearphishing) | Train users on device-code phishing patterns and 'do not approve unsolicited prompts'. |
| `M1018` | User Account Management | T1566.002 (Phishing: Spearphishing Link), T1078.004 (Valid Accounts: Cloud Accounts), T1114.002 (Email Collection: Remote Email Collection) | Disable or restrict the device-code OAuth flow via Conditional Access where feasible. |
| `M1026` | Privileged Account Management | T1078.004 (Valid Accounts: Cloud Accounts) | Use Privileged Identity Management (PIM) just-in-time access for high-value cloud roles. |
| `M1027` | Password Policies | T1078.004 (Valid Accounts: Cloud Accounts) | Enforce strong, rotated credentials and disable inactive / stale accounts. |
| `M1031` | Network Intrusion Prevention | T1566.002 (Phishing: Spearphishing Link), T1534 (Internal Spearphishing) | Detect and block phishing links; rewrite URLs and detonate at click time. |
| `M1032` | Multi-factor Authentication | T1078.004 (Valid Accounts: Cloud Accounts) | Require MFA / Conditional Access on every cloud sign-in, including service principals where supported. |
| `M1041` | Encrypt Sensitive Information | T1114.002 (Email Collection: Remote Email Collection) | Apply rights-management / sensitivity labels so exfiltrated mail is unreadable. |
| `M1047` | Audit | T1114.002 (Email Collection: Remote Email Collection) | Alert on bulk Graph mailbox reads outside business patterns. |
