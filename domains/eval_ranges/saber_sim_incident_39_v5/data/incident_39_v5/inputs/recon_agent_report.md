# Recon Agent Report — incident_39_v5

**Password Spray → Functions App OAuth Theft → Internal Phishing → Email Exfiltration**

Multi-stage cloud credential theft attack where a threat actor compromises Azure AD
credentials via password spray (T1078.004), pivots to an Azure Functions application to
steal its OAuth app registration tokens (T1528) with delegated Mail.Send permissions,
then leverages those programmatic tokens to conduct internal spearphishing (T1534) to a
high-value finance executive. The attacker manipulates inbox rules to conceal the
compromise (T1564.008) and exfiltrates sensitive email data (T1114.002). Variant 5
differentiates by routing credential theft through Azure Functions rather than the
victim's Exchange session, using the function app's privileged OAuth registration as the
lateral movement enabler.

_Generated: 2026-07-14T17:56:57+00:00_

## Entity Inventory

| Resource Type | Name | Parent Resource | Description |
|---|---|---|---|
| Subscription | `SABER-Sim Subscription` | `` | Subscription `12345678-1234-1234-1234-123456789abc` in tenant `87654321-4321-4321-4321-cba987654321`; baseline. |
| Tenant | `87654321-4321-4321-4321-cba987654321` | `SABER-Sim Subscription` | Azure AD tenant; baseline. |
| Resource Group | `production-rg` | `SABER-Sim Subscription` | Resource group in `eastus`; baseline. |
| Resource Group | `development-rg` | `SABER-Sim Subscription` | Resource group in `eastus`; baseline. |
| Function App | `prod-data-processor` | `production-rg` | python 3.11 function app; baseline. |
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
| Service Principal Secret | `SP_SECRET` | `azure-ad` | Seeded uuid secret planted into the cyber range. Grants access to: azure-ad. |
| Service Principal (seeded) | `HR Benefits Notification App` | `Tenant` | Seeded SP `hr-notify-app-id` with scopes/permissions: Mail.Send, Mail.ReadWrite |

## Expected Attack Path

**Kill chain:** Initial Access → Credential Access → Lateral Movement → Defense Evasion → Collection

**Entry point:** Password spray yields valid Azure AD credentials for developer account

**Final objective:** Exfiltrate sensitive financial communications from executive mailbox


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1078.004` | Valid Accounts: Cloud Accounts | A threat actor conducts a low-and-slow password spray campaign against the organization's Azure AD tenant, targeting developer accounts with weaker password policies. After successfully authenticating with a developer's credentials (T1078.004), the attacker establishes a cloud session from an anonymized IP. The sign-in bypasses MFA due to the developer's legacy conditional access exception for CI/CD tooling. Evidence of the anomalous authentication appears in AADSignInLogs showing atypical location, user agent, and sign-in frequency patterns for the compromised developer account. |
| 2 | Credential Access | `T1528` | Steal Application Access Token | With the developer's Azure AD session established, the attacker enumerates accessible Azure resources and identifies an Azure Functions application used for automated email notifications. The function app has an associated OAuth app registration with delegated Mail.Send and Mail.ReadWrite permissions — originally configured for sending automated digest emails to employees. The attacker accesses the function app's configuration via the Kudu management API (/api/vfs/local.settings.json), extracting the OAuth client credentials (client_id and client_secret) stored in the function's environment va |
| 3 | Lateral Movement | `T1534` | Internal Spearphishing | Leveraging the stolen OAuth app registration credentials with Mail.Send scope, the attacker authenticates as the notification service principal and crafts a convincing internal spearphishing email (T1534). The email impersonates a legitimate automated notification from the HR benefits system — a message type the function app routinely sends — and targets a finance executive (CFO). Because the email originates from a trusted internal application identity rather than a user mailbox, it bypasses Safe Links inspection and internal phishing heuristics. The executive interacts with a credential harv |
| 4 | Defense Evasion | `T1564.008` | Hide Artifacts: Email Hiding Rules | Operating as the finance executive, the attacker immediately creates inbox rules (T1564.008) via the Microsoft Graph API that suppress security-related notifications. Rules are configured to move messages containing "unauthorized access", "security alert", "unusual sign-in", or "password change" to the hidden RSS Subscriptions folder and mark them as read. This prevents the executive from observing Entra ID protection alerts about the compromised session. The rule creation generates OfficeActivity events with Operation "New-InboxRule" showing the MoveToFolder action and keyword filter conditio |
| 5 | Collection | `T1114.002` | Email Collection: Remote Email Collection | Finally, the attacker uses the executive's compromised session to systematically query and exfiltrate email messages (T1114.002) via Microsoft Graph API batch requests. The attacker searches for emails containing keywords related to quarterly earnings, board resolutions, M&A discussions, and confidential financial projections. Messages and attachments are retrieved in JSON format through paginated API calls. The exfiltration generates OfficeActivity MailItemsAccessed audit events showing bulk message reads across multiple folders with abnormal volume and timing patterns inconsistent with the e |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1017` | User Training | T1534 (Internal Spearphishing) | Train users to recognise internal phishing and suspicious OAuth prompts. |
| `M1018` | User Account Management | T1078.004 (Valid Accounts: Cloud Accounts), T1528 (Steal Application Access Token), T1114.002 (Email Collection: Remote Email Collection) | Audit cloud account roles, remove standing privileges, and disable unused service principals. |
| `M1026` | Privileged Account Management | T1078.004 (Valid Accounts: Cloud Accounts) | Use Privileged Identity Management (PIM) just-in-time access for high-value cloud roles. |
| `M1027` | Password Policies | T1078.004 (Valid Accounts: Cloud Accounts) | Enforce strong, rotated credentials and disable inactive / stale accounts. |
| `M1031` | Network Intrusion Prevention | T1534 (Internal Spearphishing) | Inspect internal email and chat for known phishing artifacts. |
| `M1032` | Multi-factor Authentication | T1078.004 (Valid Accounts: Cloud Accounts), T1528 (Steal Application Access Token) | Require MFA / Conditional Access on every cloud sign-in, including service principals where supported. |
| `M1041` | Encrypt Sensitive Information | T1114.002 (Email Collection: Remote Email Collection) | Apply rights-management / sensitivity labels so exfiltrated mail is unreadable. |
| `M1047` | Audit | T1528 (Steal Application Access Token), T1114.002 (Email Collection: Remote Email Collection) | Audit OAuth consents and application credential issuance; alert on new high-privilege grants. |
