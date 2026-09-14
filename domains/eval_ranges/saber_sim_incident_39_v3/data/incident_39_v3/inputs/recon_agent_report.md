# Recon Agent Report — incident_39_v3

**Cloud Account Compromise → OAuth Token Theft → Internal Phishing → Email Exfiltration**

Cloud credential theft attack where a threat actor leverages compromised cloud accounts
(T1078.004) to steal OAuth application tokens (T1528), then pivots laterally via internal
spearphishing to a high-value target. The attacker manipulates inbox rules to conceal
activity and exfiltrates sensitive email data. Variant 3 features a distinct lateral
movement path: the attacker chains from the initial compromised identity through the
first victim's mailbox to phish a second user, rather than directly escalating privileges
on the original account.

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
| Service Principal (seeded) | `Document Viewer Pro` | `Tenant` | Seeded SP `doc-viewer-pro-app-id` with scopes/permissions:  |

## Expected Attack Path

**Kill chain:** Initial Access → Credential Access → Lateral Movement → Defense Evasion → Collection

**Entry point:** Compromised cloud account credentials used for Azure AD sign-in

**Final objective:** Email collection and exfiltration from target mailbox via Graph API


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1078.004` | Valid Accounts: Cloud Accounts | A threat actor begins with compromised cloud account credentials obtained through credential stuffing against the organization's Azure AD tenant. Using these valid credentials (T1078.004), the attacker authenticates to Azure AD, establishing a session that appears legitimate in AADSignInLogs. The sign-in originates from an unusual IP address and location compared to the victim's baseline, but passes basic authentication without triggering MFA due to a conditional access policy gap. |
| 2 | Credential Access | `T1528` | Steal Application Access Token | From the compromised Azure AD session, the attacker extracts an OAuth application access token (T1528) scoped to Mail.ReadWrite on Exchange Online. The attacker leverages the authenticated session to consent to a malicious OAuth application or extracts tokens from the session's token cache, obtaining persistent API-level access to the first victim's mailbox without requiring further interactive sign-in. This token theft is visible in AADSignInLogs as an unusual application consent or token issuance event. |
| 3 | Lateral Movement | `T1534` | Internal Spearphishing | With Exchange Online access via the stolen OAuth token, the attacker crafts a convincing internal spearphishing message (T1534) sent from the first victim's legitimate mailbox to a high-value second target — a finance director with access to sensitive financial communications. The internal origin bypasses external email filtering and trust indicators. The second victim, seeing a message from a known colleague with a legitimate sender address, clicks a credential harvesting link or OAuth consent prompt, yielding their access token to the attacker. This activity generates OfficeActivity logs sho |
| 4 | Defense Evasion | `T1564.008` | Hide Artifacts: Email Hiding Rules | Now operating as the second victim, the attacker creates inbox rules (T1564.008) on the target mailbox via the Microsoft Graph API. These rules automatically move messages containing keywords like "unauthorized", "security alert", "password reset", or "suspicious" to a hidden RSS Feeds folder and mark them as read. This prevents the second victim from noticing security notifications about the unauthorized access. The rule creation appears in OfficeActivity with Operation "New-InboxRule" and parameters revealing the suppression conditions. |
| 5 | Collection | `T1114.002` | Email Collection: Remote Email Collection | Finally, the attacker uses the second victim's token to systematically collect email messages (T1114.002) from the target mailbox via the Microsoft Graph API, exfiltrating sensitive communications including financial reports, board meeting minutes, M&A discussions, and confidential attachments. The attacker queries specific mail folders and uses search filters to identify high-value messages. Evidence of this activity appears across AADSignInLogs (anomalous sign-in patterns for both victims), OfficeActivity (mailbox access, rule creation, and bulk message reads), and CloudAppEvents (OAuth toke |

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
