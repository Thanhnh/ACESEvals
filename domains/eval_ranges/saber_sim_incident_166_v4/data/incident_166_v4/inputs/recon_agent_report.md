# Recon Agent Report — incident_166_v4

**Spearphishing Link → Azure AD Sign-In → Directory Enumeration → Internal Spearphishing → Executive Email Exfiltration**

Multi-stage cloud identity attack leveraging social engineering at two distinct stages.
A threat actor delivers a credential harvester via spearphishing link, uses the harvested
credentials to sign into the victim's Azure AD account, enumerates directory users to
identify high-value executive targets, then conducts internal spearphishing from the
compromised mailbox to laterally move to an executive account. The attack culminates in
email collection from the executive's mailbox. Variant 4 distinguishes itself through its
lateral movement path via internal spearphishing (T1534) rather than direct credential
abuse, requiring a second social engineering interaction to compromise the executive.

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
| Credential (password) | `EXEC_AD_CREDENTIALS` | `azure-ad` | Seeded password planted into the cyber range. Grants access to: azure-ad. |

## Expected Attack Path

**Kill chain:** Initial Access → Defense Evasion → Discovery → Lateral Movement → Collection

**Entry point:** Spearphishing link delivering credential harvester page targeting victim's Azure AD credentials

**Final objective:** Exfiltrate sensitive email from executive (CFO) mailbox via Microsoft Graph Mail API


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1566.002` | Phishing: Spearphishing Link | A threat actor initiates a multi-stage identity attack against a corporate Azure AD tenant by sending a spearphishing email containing a link to a convincing credential harvester page that mimics the Microsoft Azure AD sign-in portal. The targeted victim, a mid-level employee with broad directory read permissions (User.Read.All), clicks the link and enters their corporate credentials on the fake page. |
| 2 | Defense Evasion | `T1078.004` | Valid Accounts: Cloud Accounts | Armed with the victim's username and password, the attacker authenticates to Azure AD via the OAuth2 token endpoint, obtaining an access token with User.Read.All, Mail.ReadWrite, and Mail.Send scopes. This sign-in generates an entry in AADSignInLogs showing authentication from an anomalous IP address not previously associated with the victim's account. The sign-in uses single-factor authentication (no MFA challenge triggered due to weak Conditional Access policy that only enforces MFA for privileged roles). |
| 3 | Discovery | `T1087.004` | Account Discovery: Cloud Account | The attacker leverages the victim's directory read permissions to enumerate all users in the Azure AD tenant via the Microsoft Graph /v1.0/users endpoint. This discovery phase identifies the CFO and other C-suite executives as high-value targets. The Graph API calls generate non-interactive sign-in entries in AADSignInLogs showing resource access to Microsoft Graph. |
| 4 | Lateral Movement | `T1534` | Internal Spearphishing | Rather than attempting direct credential abuse against the executive (which would trigger the MFA policy enforced for privileged roles), the attacker pivots to the victim's Exchange Online mailbox. Using the victim's Mail.Send scope, the attacker crafts a convincing internal email to the CFO — appearing to come from a trusted colleague regarding a routine business matter (quarterly budget review requiring urgent sign-off). This internal spearphishing technique (T1534) exploits trust between internal users, bypassing external email security controls and Safe Links policies that only scan extern |
| 5 | Collection | `T1114.002` | Email Collection: Remote Email Collection | The CFO, seeing an email from a known internal colleague regarding a plausible business matter, clicks the embedded link and enters their credentials on the harvester page. The attacker now possesses the executive's Azure AD credentials and authenticates as the CFO. This second sign-in in AADSignInLogs shows the same anomalous attacker IP now associated with a privileged user, with RiskLevelDuringSignIn elevated to medium due to IP reputation signals. |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1017` | User Training | T1566.002 (Phishing: Spearphishing Link), T1534 (Internal Spearphishing) | Train users on device-code phishing patterns and 'do not approve unsolicited prompts'. |
| `M1018` | User Account Management | T1566.002 (Phishing: Spearphishing Link), T1078.004 (Valid Accounts: Cloud Accounts), T1087.004 (Account Discovery: Cloud Account), T1114.002 (Email Collection: Remote Email Collection) | Disable or restrict the device-code OAuth flow via Conditional Access where feasible. |
| `M1026` | Privileged Account Management | T1078.004 (Valid Accounts: Cloud Accounts) | Use Privileged Identity Management (PIM) just-in-time access for high-value cloud roles. |
| `M1027` | Password Policies | T1078.004 (Valid Accounts: Cloud Accounts) | Enforce strong, rotated credentials and disable inactive / stale accounts. |
| `M1031` | Network Intrusion Prevention | T1566.002 (Phishing: Spearphishing Link), T1534 (Internal Spearphishing) | Detect and block phishing links; rewrite URLs and detonate at click time. |
| `M1032` | Multi-factor Authentication | T1078.004 (Valid Accounts: Cloud Accounts) | Require MFA / Conditional Access on every cloud sign-in, including service principals where supported. |
| `M1041` | Encrypt Sensitive Information | T1114.002 (Email Collection: Remote Email Collection) | Apply rights-management / sensitivity labels so exfiltrated mail is unreadable. |
| `M1047` | Audit | T1087.004 (Account Discovery: Cloud Account), T1114.002 (Email Collection: Remote Email Collection) | Alert on bulk user / SP enumeration via Graph. |
