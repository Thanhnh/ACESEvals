# Recon Agent Report — incident_134_v2

**OAuth Consent Phishing → ARM Discovery → App Credential Persistence → BEC Wire Fraud**

Multi-stage Business Email Compromise exploiting OAuth application consent phishing with
credential persistence via service principal password addition. The attacker registers a
malicious OAuth application requesting Mail.Read, Mail.ReadWrite, and Mail.Send delegated
permissions, then crafts an authorization URL that lures the victim into granting consent.
After obtaining the delegated token, the attacker enumerates tenant resources via ARM API
to confirm access scope, then establishes persistence by adding a client secret to the
malicious app registration. Using the persistent credential, the attacker reconnoiters the
victim's mailbox for financial communications, creates inbox rules to suppress reply-chain
evidence, and sends a wire transfer fraud email impersonating the compromised user to an
external financial controller.

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

**Kill chain:** Initial Access → Discovery → Persistence → Collection → Defense Evasion → Impact

**Entry point:** Malicious OAuth application consent phishing via crafted authorization URL

**Final objective:** Send wire transfer fraud email impersonating compromised user to external financial target


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1566.002` | Phishing: Spearphishing Link | A threat actor registers a malicious multi-tenant OAuth application in an attacker-controlled Azure AD tenant, configuring it to request Mail.Read, Mail.ReadWrite, and Mail.Send delegated permissions. They construct a crafted authorization URL (with response_type=code and the malicious app's client_id) and deliver it to the victim via a spearphishing email disguised as a legitimate Microsoft service notification. |
| 2 | Discovery | `T1580` | Cloud Infrastructure Discovery | When the victim clicks the consent link and approves the permission dialog, Azure AD issues an authorization code to the attacker's registered redirect URI. The attacker exchanges this code for a delegated access token with full mailbox permissions on behalf of the victim. |
| 3 | Persistence | `T1098.001` | Account Manipulation: Additional Cloud Credentials | With the delegated token in hand, the attacker first queries the Azure Resource Manager API to enumerate subscriptions and resource groups in the victim's tenant. This confirms the token's validity and scope, and reveals the organizational structure — identifying which subscription contains Exchange-related resources and service principals. |
| 4 | Collection | `T1114.002` | Email Collection: Remote Email Collection | The attacker then establishes persistence by calling the Microsoft Graph servicePrincipals addPassword endpoint, adding a new client secret to the malicious application's service principal. This ensures continued access independent of the victim's session — even if the delegated token expires or the victim revokes consent, the attacker can re-authenticate using the app credential with client_credentials flow. |
| 5 | Defense Evasion | `T1564.008` | Hide Artifacts: Email Hiding Rules | Using the persistent app credential to obtain a fresh Graph API token, the attacker programmatically searches the victim's mailbox (via /users/{id}/messages with $filter and $search parameters) for financial keywords: "wire transfer," "payment instructions," "bank details," "invoice." They identify an active thread between the victim and an external financial controller regarding a pending $2.4M transfer. |
| 6 | Impact | `T1534` | Internal Spearphishing | To suppress detection of the impersonation, the attacker creates an inbox rule via the Graph API mailFolders/inbox/messageRules endpoint. The rule moves any replies from the targeted financial controller's email address to the RSS Feeds folder, preventing the victim from seeing responses to the fraudulent message. |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1017` | User Training | T1566.002 (Phishing: Spearphishing Link), T1534 (Internal Spearphishing) | Train users on device-code phishing patterns and 'do not approve unsolicited prompts'. |
| `M1018` | User Account Management | T1566.002 (Phishing: Spearphishing Link), T1580 (Cloud Infrastructure Discovery), T1114.002 (Email Collection: Remote Email Collection) | Disable or restrict the device-code OAuth flow via Conditional Access where feasible. |
| `M1031` | Network Intrusion Prevention | T1566.002 (Phishing: Spearphishing Link), T1534 (Internal Spearphishing) | Detect and block phishing links; rewrite URLs and detonate at click time. |
| `M1041` | Encrypt Sensitive Information | T1114.002 (Email Collection: Remote Email Collection) | Apply rights-management / sensitivity labels so exfiltrated mail is unreadable. |
| `M1047` | Audit | T1580 (Cloud Infrastructure Discovery), T1114.002 (Email Collection: Remote Email Collection) | Alert on high-volume ARM enumeration (listKeys, listResources) by non-automation principals. |
