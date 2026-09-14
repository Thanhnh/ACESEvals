# Recon Agent Report — incident_134_v5

**Device Code Phishing → ARM Discovery → Exchange BEC Fraud**

Multi-stage Business Email Compromise (BEC) attack leveraging Azure AD device code
phishing as the initial access vector. The attacker harvests a victim executive's
OAuth token via the device code flow, performs ARM-based organizational discovery
to identify high-value wire transfer approvers, accesses the victim's Exchange Online
mailbox to gather financial context (recent invoices, payment schedules), creates
inbox rules to hide reply evidence of the compromise, and sends fraudulent wire
transfer requests impersonating the compromised executive to the finance department.
Variant 5 differentiates by using device code phishing (rather than OAuth redirect
or consent grant) and ARM-based organizational discovery for target selection.

_Generated: 2026-07-14T17:56:57+00:00_

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

**Kill chain:** Initial Access → Discovery → Collection → Defense Evasion → Impact

**Entry point:** Device code phishing via Azure AD device code flow

**Final objective:** Send fraudulent wire transfer request impersonating compromised executive (BEC)


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1566.002` | Phishing: Spearphishing Link | A threat actor targets a victim executive (e.g., CFO or VP of Finance) with a device code phishing attack. The attacker initiates the Azure AD device code flow using a legitimate Microsoft application client ID, generating a user code. This code is delivered to the victim via a social engineering pretext — such as a fake MFA prompt, IT support request, or document access notification — enticing the victim to enter the code at microsoft.com/devicelogin. |
| 2 | Discovery | `T1087.004` | Account Discovery: Cloud Account | Once the victim authenticates and approves the device code, the attacker's polling loop receives a valid OAuth access token and refresh token bound to the victim's identity. This token grants the attacker delegated access to all resources the victim can access, without triggering password-based alerts. The sign-in appears in AADSignInLogs with AuthenticationProtocol=deviceCode from the attacker's IP address. |
| 3 | Collection | `T1114.002` | Email Collection: Remote Email Collection | With the victim's OAuth token, the attacker queries the Azure Resource Manager (ARM) API to perform organizational discovery. They enumerate subscriptions, resource groups, and user directory information to identify high-value targets — specifically, employees in the finance department who have authority to approve wire transfers. This ARM-based discovery (rather than simple Exchange GAL enumeration) is characteristic of Variant 5 and generates AzureActivityLogs entries showing rapid GET requests across resource providers. |
| 4 | Defense Evasion | `T1564.008` | Hide Artifacts: Email Hiding Rules | Next, the attacker accesses the victim's Exchange Online mailbox via Microsoft Graph API. They search for recent invoices, payment schedules, vendor correspondence, and wire transfer approvals to understand the organization's financial processes, typical transaction amounts, and communication patterns. OfficeActivity logs show bulk MailItemsAccessed operations from the attacker's IP. |
| 5 | Impact | `T1534` | Internal Spearphishing | To maintain stealth, the attacker creates inbox rules on the victim's mailbox that automatically move any replies from the identified finance targets to a hidden folder (e.g., "RSS Subscriptions" or a custom folder). This prevents the victim from seeing responses to the fraudulent emails, buying the attacker time. The OfficeActivity log records a New-InboxRule operation with MoveToFolder action targeting specific senders. |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1017` | User Training | T1566.002 (Phishing: Spearphishing Link), T1534 (Internal Spearphishing) | Train users on device-code phishing patterns and 'do not approve unsolicited prompts'. |
| `M1018` | User Account Management | T1566.002 (Phishing: Spearphishing Link), T1087.004 (Account Discovery: Cloud Account), T1114.002 (Email Collection: Remote Email Collection) | Disable or restrict the device-code OAuth flow via Conditional Access where feasible. |
| `M1031` | Network Intrusion Prevention | T1566.002 (Phishing: Spearphishing Link), T1534 (Internal Spearphishing) | Detect and block phishing links; rewrite URLs and detonate at click time. |
| `M1041` | Encrypt Sensitive Information | T1114.002 (Email Collection: Remote Email Collection) | Apply rights-management / sensitivity labels so exfiltrated mail is unreadable. |
| `M1047` | Audit | T1087.004 (Account Discovery: Cloud Account), T1114.002 (Email Collection: Remote Email Collection) | Alert on bulk user / SP enumeration via Graph. |
