# Recon Agent Report — incident_134_v1

**Spearphishing Credential Harvest → Azure AD Auth → Inbox Rule Suppression → BEC Wire Fraud**

Classic Business Email Compromise (BEC) attack chain where a threat actor harvests corporate
credentials via a spearphishing link, authenticates to Azure AD as the compromised victim,
creates inbox rules to suppress reply notifications (hiding evidence of the attack), and
sends fraudulent wire transfer requests to finance personnel. Evidence spans AADSignInLogs
(anomalous sign-in from attacker infrastructure), OfficeActivity (inbox rule creation and
outbound email), and SecurityAlert (phishing detection and impossible travel alerts).

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

**Kill chain:** Initial Access → Defense Evasion → Discovery → Defense Evasion → Impact

**Entry point:** Credential harvest phishing email with spearphishing link to fake login portal

**Final objective:** Send fraudulent wire transfer BEC email impersonating the compromised executive


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1566.002` | Phishing: Spearphishing Link | A threat actor conducts reconnaissance on a mid-sized organization and identifies an executive target (VP of Operations) whose email address is publicly available. |
| 2 | Defense Evasion | `T1078.004` | Valid Accounts: Cloud Accounts | STEP 1 — INITIAL ACCESS (T1566.002): The attacker crafts a convincing spearphishing email containing a link to a credential harvesting page that mimics the corporate Microsoft 365 login portal. The victim clicks the link and enters their Azure AD credentials, which are captured by the attacker's infrastructure. Microsoft Defender for Office 365 generates a SecurityAlert post-delivery with AlertName "Phishing email delivered to inbox", CompromisedEntity set to the victim's UserPrincipalName, AlertSeverity "Medium", and ProviderName "Office 365 Advanced Threat Protection". The Entities field con |
| 3 | Discovery | `T1087.004` | Account Discovery: Cloud Account | STEP 2 — DEFENSE EVASION (T1078.004): Using the harvested credentials, the attacker authenticates to Azure AD as the victim from an anomalous IP address (foreign VPN endpoint). The sign-in succeeds (ResultType: 0) and generates an AADSignInLogs entry with the victim's UserPrincipalName, a non-corporate IPAddress, suspicious Location (country different from victim's baseline), and an unfamiliar UserAgent/DeviceDetail. AppDisplayName shows "Microsoft Office 365" and ResourceDisplayName shows "Office 365 Exchange Online". The attacker obtains an OAuth token with Mail.ReadWrite and Mail.Send scope |
| 4 | Defense Evasion | `T1564.008` | Hide Artifacts: Email Hiding Rules | STEP 3 — DISCOVERY (T1087.004): The attacker enumerates the victim's mailbox contacts, organizational hierarchy, and recent email threads to identify high-value BEC targets. They discover active communication with the CFO regarding an upcoming vendor payment of $287,000. OfficeActivity logs show Operation "MailItemsAccessed" with MailAccessType "Bind" and "Sync" as the attacker reads mail items. ClientIP matches the anomalous IP from the AADSignInLogs entry. UserId shows the victim's email, and OfficeWorkload is "Exchange". Multiple AffectedItems entries indicate bulk access to Inbox and Sent  |
| 5 | Impact | `T1534` | Internal Spearphishing | STEP 4 — DEFENSE EVASION (T1564.008): The attacker creates an inbox rule that automatically moves replies containing keywords like "wire", "payment", "transfer", or "verify" to the RSS Feeds folder and marks them as read. This prevents the legitimate account owner from noticing responses to the forthcoming BEC email. OfficeActivity logs record Operation "New-InboxRule" with ResultStatus "True". The Parameters field contains the rule definition: Name ".", Conditions with SubjectOrBodyContainsWords ["wire","payment","transfer","verify","bank details"], Actions with MoveToFolder "RSS Feeds" and M |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1017` | User Training | T1566.002 (Phishing: Spearphishing Link), T1534 (Internal Spearphishing) | Train users on device-code phishing patterns and 'do not approve unsolicited prompts'. |
| `M1018` | User Account Management | T1566.002 (Phishing: Spearphishing Link), T1078.004 (Valid Accounts: Cloud Accounts), T1087.004 (Account Discovery: Cloud Account) | Disable or restrict the device-code OAuth flow via Conditional Access where feasible. |
| `M1026` | Privileged Account Management | T1078.004 (Valid Accounts: Cloud Accounts) | Use Privileged Identity Management (PIM) just-in-time access for high-value cloud roles. |
| `M1027` | Password Policies | T1078.004 (Valid Accounts: Cloud Accounts) | Enforce strong, rotated credentials and disable inactive / stale accounts. |
| `M1031` | Network Intrusion Prevention | T1566.002 (Phishing: Spearphishing Link), T1534 (Internal Spearphishing) | Detect and block phishing links; rewrite URLs and detonate at click time. |
| `M1032` | Multi-factor Authentication | T1078.004 (Valid Accounts: Cloud Accounts) | Require MFA / Conditional Access on every cloud sign-in, including service principals where supported. |
| `M1047` | Audit | T1087.004 (Account Discovery: Cloud Account) | Alert on bulk user / SP enumeration via Graph. |
