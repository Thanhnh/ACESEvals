# Recon Agent Report — incident_166_v3

**Spearphishing Link → Azure AD Compromise → Internal Phishing → Executive Email Exfiltration**

Variant 3 of a phishing-to-cloud-compromise attack chain. A threat actor delivers a credential
harvesting link via spearphishing, compromises an Azure AD cloud account, then leverages the
compromised mailbox to send internal spearphishing to a high-value executive. The lateral
movement via internal phishing distinguishes this variant, enabling access to executive mail
for collection and exfiltration. The attack exploits implicit trust in internal senders and
the difficulty of detecting credential-based access from legitimate cloud accounts.

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

## Expected Attack Path

**Kill chain:** Initial Access → Discovery → Lateral Movement → Privilege Escalation → Collection

**Entry point:** Spearphishing link with credential harvesting page targeting employee

**Final objective:** Exfiltrate executive mailbox contents via Microsoft Graph API


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1566.002` | Phishing: Spearphishing Link | A threat actor initiates the attack by sending a spearphishing email containing a link to a credential harvesting page to an employee (victim1) within the target organization. The email impersonates a legitimate service (e.g., IT password reset, SharePoint document share) and directs the victim to a convincing Azure AD login page that initiates a device code authentication flow. When victim1 enters the device code, the attacker captures the resulting OAuth token (VICTIM1_OAUTH_TOKEN) with Mail.Read and Mail.Send scopes. |
| 2 | Discovery | `T1087.004` | Account Discovery: Cloud Account | With authenticated access to Azure AD via the victim's delegated token, the attacker enumerates the organization's cloud directory to identify high-value targets. The attacker queries Azure AD user information and reviews victim1's mailbox contacts and recent correspondence to identify C-level executives, specifically the CFO or CEO, who would have access to sensitive financial communications and strategic planning documents. |
| 3 | Lateral Movement | `T1534` | Internal Spearphishing | The attacker then leverages victim1's compromised Exchange Online mailbox to craft and send a highly targeted internal spearphishing email to the identified executive. The email is sent via Microsoft Graph's sendMail API using victim1's OAuth token, making it appear as legitimate internal communication from a trusted colleague. Because the email originates from a real internal sender with valid DKIM/SPF alignment, it bypasses external email security controls and exploits the implicit trust between colleagues. The phishing email contains a credential harvesting link disguised as an urgent docum |
| 4 | Privilege Escalation | `T1078.004` | Valid Accounts: Cloud Accounts | Armed with the executive's credentials, the attacker authenticates to Azure AD as the executive, obtaining a new OAuth token (EXEC_OAUTH_TOKEN) with full access to the executive's cloud resources. This authentication generates a sign-in event in AADSignInLogs but appears legitimate since it uses valid credentials and may originate from a similar geographic region if the attacker uses residential proxies. |
| 5 | Collection | `T1114.002` | Email Collection: Remote Email Collection | Finally, the attacker uses the executive's OAuth token to access their Exchange Online mailbox via Microsoft Graph API, performing systematic email collection targeting sensitive communications including board meeting minutes, financial reports, M&A discussions, strategic planning documents, and communications with legal counsel. The collected emails are exfiltrated through Graph API read operations, leaving traces in OfficeActivity logs as MailItemsAccessed and MessageBind operations under the executive's identity. |

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
