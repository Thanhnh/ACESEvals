# Recon Agent Report — incident_39_v1

**Compromised Azure AD Credentials → OAuth Token Theft → Inbox Rule Evasion → Bulk Email Exfiltration**

Multi-stage cloud credential theft attack where an adversary leverages compromised
Azure AD credentials (T1078.004) to authenticate, then steals OAuth application
access tokens (T1528) to gain persistent API access. The attacker enumerates cloud
accounts to identify high-value targets, creates inbox rules to suppress security
notifications (defense evasion), and performs bulk email collection (T1114.002) for
data exfiltration. Evidence spans AADSignInLogs, CloudAppEvents, and OfficeActivity.

_Generated: 2026-07-14T17:56:58+00:00_

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
| Service Principal Secret | `SP_SECRET` | `azure-ad` | Seeded uuid secret planted into the cyber range. Grants access to: azure-ad. |
| Service Principal (seeded) | `Mail Daemon Service Principal` | `Tenant` | Seeded SP `mail-daemon-app-id` with scopes/permissions: Mail.Read, Mail.ReadWrite, MailboxSettings.ReadWrite, User.Read.All |

## Expected Attack Path

**Kill chain:** Initial Access → Credential Access → Discovery → Defense Evasion → Collection

**Entry point:** Compromised Azure AD credentials used for cloud account sign-in

**Final objective:** Bulk email collection and exfiltration from high-value target mailboxes


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1078.004` | Valid Accounts: Cloud Accounts | A threat actor possessing previously compromised Azure AD credentials for a corporate user account initiates the attack by authenticating to Azure AD via the Microsoft identity platform. The sign-in event appears in AADSignInLogs with fields including UserPrincipalName, IPAddress, AppDisplayName, ResultType, RiskLevelDuringSignIn, and ConditionalAccessStatus — potentially showing anomalous location, unfamiliar AppId, or elevated risk scores compared to the legitimate user's baseline. |
| 2 | Credential Access | `T1528` | Steal Application Access Token | Upon successful authentication (T1078.004), the attacker leverages the authenticated session to steal OAuth application access tokens (T1528). This involves accessing OAuth2 token endpoints with application scopes including Mail.ReadWrite and Mail.Send, effectively extracting delegated tokens that provide persistent API-level access to Microsoft Graph resources. This token theft activity generates events in CloudAppEvents with ActionType values related to consent grants or token issuance, capturing AccountObjectId, Application, IPAddress, and ActivityObjects fields that reveal the scope escala |
| 3 | Discovery | `T1087.004` | Account Discovery: Cloud Account | With the OAuth application token in hand, the attacker enumerates cloud accounts (T1087.004) through Microsoft Graph API directory queries, identifying high-value targets such as executives, finance personnel, and IT administrators. These enumeration calls appear in CloudAppEvents as directory read operations with ActionType indicating user listing or directory enumeration, ObjectType showing User entities, and the same compromised AccountObjectId from the initial access. |
| 4 | Defense Evasion | `T1564.008` | Hide Artifacts: Email Hiding Rules | Before performing data collection, the attacker creates inbox rules (T1564.008) on the target mailboxes to suppress security notification emails — moving password reset confirmations, MFA alerts, and suspicious sign-in notifications to deleted items or a hidden folder. This defense evasion step prevents the victim from being alerted to the compromise. The rule creation is logged in OfficeActivity with Operation value "New-InboxRule" and Parameters showing conditions that match known malicious patterns (matching subjects like "security alert", "password reset", "unusual sign-in" and actions mov |
| 5 | Collection | `T1114.002` | Email Collection: Remote Email Collection | Finally, the attacker performs bulk email collection (T1114.002) across the identified high-value mailboxes, accessing message contents via the Graph Mail API. The OfficeActivity logs capture these with Operation "MailItemsAccessed" showing elevated ItemCount values, ExternalAccess set to true, LogonType indicating non-owner access, and ClientInfoString revealing programmatic API client patterns rather than normal Outlook or OWA user agents — indicating automated harvesting rather than interactive email usage. |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1018` | User Account Management | T1078.004 (Valid Accounts: Cloud Accounts), T1528 (Steal Application Access Token), T1087.004 (Account Discovery: Cloud Account), T1114.002 (Email Collection: Remote Email Collection) | Audit cloud account roles, remove standing privileges, and disable unused service principals. |
| `M1026` | Privileged Account Management | T1078.004 (Valid Accounts: Cloud Accounts) | Use Privileged Identity Management (PIM) just-in-time access for high-value cloud roles. |
| `M1027` | Password Policies | T1078.004 (Valid Accounts: Cloud Accounts) | Enforce strong, rotated credentials and disable inactive / stale accounts. |
| `M1032` | Multi-factor Authentication | T1078.004 (Valid Accounts: Cloud Accounts), T1528 (Steal Application Access Token) | Require MFA / Conditional Access on every cloud sign-in, including service principals where supported. |
| `M1041` | Encrypt Sensitive Information | T1114.002 (Email Collection: Remote Email Collection) | Apply rights-management / sensitivity labels so exfiltrated mail is unreadable. |
| `M1047` | Audit | T1528 (Steal Application Access Token), T1087.004 (Account Discovery: Cloud Account), T1114.002 (Email Collection: Remote Email Collection) | Audit OAuth consents and application credential issuance; alert on new high-privilege grants. |
