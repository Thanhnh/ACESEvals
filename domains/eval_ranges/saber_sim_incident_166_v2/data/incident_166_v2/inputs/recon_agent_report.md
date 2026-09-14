# Recon Agent Report — incident_166_v2

**Spearphishing → Azure AD Compromise → Internal Phishing → Mail Collection**

Multi-stage cloud attack beginning with a spearphishing link that delivers a credential
harvester page. The attacker uses harvested credentials to compromise an Azure AD cloud
account, performs account discovery to identify high-value targets, then leverages the
compromised mailbox for internal spearphishing to laterally move to a second user account.
The final objective is remote email collection from the second compromised user's mailbox.
Variant 2 follows a distinct lateral movement path using internal spearphishing rather
than direct privilege escalation.

_Generated: 2026-07-14T17:56:59+00:00_

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
| Credential (password) | `USER_B_CREDENTIALS` | `azure-ad` | Seeded password planted into the cyber range. Grants access to: azure-ad. |

## Expected Attack Path

**Kill chain:** Initial Access → Discovery → Lateral Movement → Credential Access → Collection

**Entry point:** Spearphishing link delivering credential harvester page

**Final objective:** Exfiltrate email from laterally-compromised user mailbox


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1566.002` | Phishing: Spearphishing Link | A threat actor crafts a spearphishing email containing a link to a credential harvester page mimicking the organization's Azure AD login portal. The phishing email is delivered to User A, a mid-level employee. When User A clicks the link and enters their credentials, the attacker captures the username and password. |
| 2 | Discovery | `T1087.004` | Account Discovery: Cloud Account | Using the harvested credentials, the attacker authenticates to Azure AD as User A (T1078.004), obtaining an OAuth access token. Evidence of this anomalous sign-in appears in AADSignInLogs with unusual location/device characteristics triggering a SecurityAlert. |
| 3 | Lateral Movement | `T1534` | Internal Spearphishing | With User A's token, the attacker queries Azure Resource Manager to enumerate cloud accounts and identify high-value targets (T1087.004). The attacker identifies User B, a finance team member with access to sensitive communications. |
| 4 | Credential Access | `T1078.004` | Valid Accounts: Cloud Accounts | Leveraging User A's compromised Exchange Online access, the attacker sends a convincing internal spearphishing message (T1534) to User B. Because the email originates from a trusted internal account, User B clicks the embedded credential harvester link and submits their credentials. This activity is logged in OfficeActivity and EmailEvents. |
| 5 | Collection | `T1114.002` | Email Collection: Remote Email Collection | The attacker authenticates as User B using the newly harvested credentials (T1078.004), obtaining a fresh OAuth token. This second anomalous sign-in generates additional entries in AADSignInLogs and may trigger SecurityAlert correlation rules. |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1017` | User Training | T1566.002 (Phishing: Spearphishing Link), T1534 (Internal Spearphishing) | Train users on device-code phishing patterns and 'do not approve unsolicited prompts'. |
| `M1018` | User Account Management | T1566.002 (Phishing: Spearphishing Link), T1087.004 (Account Discovery: Cloud Account), T1078.004 (Valid Accounts: Cloud Accounts), T1114.002 (Email Collection: Remote Email Collection) | Disable or restrict the device-code OAuth flow via Conditional Access where feasible. |
| `M1026` | Privileged Account Management | T1078.004 (Valid Accounts: Cloud Accounts) | Use Privileged Identity Management (PIM) just-in-time access for high-value cloud roles. |
| `M1027` | Password Policies | T1078.004 (Valid Accounts: Cloud Accounts) | Enforce strong, rotated credentials and disable inactive / stale accounts. |
| `M1031` | Network Intrusion Prevention | T1566.002 (Phishing: Spearphishing Link), T1534 (Internal Spearphishing) | Detect and block phishing links; rewrite URLs and detonate at click time. |
| `M1032` | Multi-factor Authentication | T1078.004 (Valid Accounts: Cloud Accounts) | Require MFA / Conditional Access on every cloud sign-in, including service principals where supported. |
| `M1041` | Encrypt Sensitive Information | T1114.002 (Email Collection: Remote Email Collection) | Apply rights-management / sensitivity labels so exfiltrated mail is unreadable. |
| `M1047` | Audit | T1087.004 (Account Discovery: Cloud Account), T1114.002 (Email Collection: Remote Email Collection) | Alert on bulk user / SP enumeration via Graph. |
