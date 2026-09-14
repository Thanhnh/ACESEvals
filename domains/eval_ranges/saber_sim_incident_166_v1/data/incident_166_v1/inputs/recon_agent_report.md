# Recon Agent Report — incident_166_v1

**German Anonymous Spray → Contact Discovery → ITCleanup Rule → BEC Wire Fraud → SAP Financial Exfil**

A financially-motivated threat actor leverages anonymous VPN nodes across Hamburg
and Frankfurt, Germany to conduct a distributed password spray against Azure AD.
Upon compromising a corporate account, the attacker enumerates mailbox contacts
to identify SAP procurement stakeholders, deploys a defense-evasion inbox rule
("ITCleanup") to suppress bounce-back notifications, executes a BEC wire fraud
against an external procurement partner using SAP purchase order context, and
pivots to the organization's SAP web application via Azure AD SSO to harvest
business-critical financial records.

_Generated: 2026-07-14T17:56:59+00:00_

## Entity Inventory

| Resource Type | Name | Parent Resource | Description |
|---|---|---|---|
| Subscription | `SABER-Sim Subscription` | `` | Subscription `12345678-1234-1234-1234-123456789abc` in tenant `87654321-4321-4321-4321-cba987654321`; baseline. |
| Tenant | `87654321-4321-4321-4321-cba987654321` | `SABER-Sim Subscription` | Azure AD tenant; baseline. |
| Resource Group | `production-rg` | `SABER-Sim Subscription` | Resource group in `eastus`; baseline. |
| Resource Group | `development-rg` | `SABER-Sim Subscription` | Resource group in `eastus`; baseline. |
| App Service | `prod-webapp` | `production-rg` | node 20 app service; baseline. |
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

**Kill chain:** Credential Access → Initial Access → Discovery → Defense Evasion → Impact → Collection

**Entry point:** Distributed password spray from anonymous German VPN nodes (Hamburg/Frankfurt)

**Final objective:** BEC wire fraud targeting procurement partner and SAP financial data harvesting via SSO


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Credential Access | `T1110.003` | Brute Force: Password Spraying | A financially-motivated threat actor initiates a distributed password spray campaign from an anonymous VPN exit node in Hamburg, Germany (IPAddress: 185.220.101.42). The spray targets dozens of Azure AD user accounts with commonly reused passwords. AADSignInLogs capture 20-50 failed authentications with ResultType='50126' and ResultDescription='Invalid username or password' from the Hamburg source IPAddress across multiple UserPrincipalName values within a compressed 10-minute window. Each failed event shows Location='DE', LocationDetails.city='Hamburg', AuthenticationRequirement='singleFactor |
| 2 | Initial Access | `T1078.004` | Valid Accounts: Cloud Accounts | The attacker pivots to a second anonymous VPN node in Frankfurt, Germany (IPAddress: 91.132.147.168) and authenticates to Azure AD. The successful sign-in generates an AADSignInLogs entry with AppDisplayName='Microsoft Graph', ResourceDisplayName='Microsoft Graph', ResourceId matching Graph API, Location='DE', LocationDetails.city='Frankfurt', IsInteractive=true, and ResultType='0'. The geographic hop from Hamburg to Frankfurt within minutes produces RiskLevelDuringSignIn='medium' via impossible-travel heuristics. Critically, ConditionalAccessStatus='notApplied' confirms no blocking policy tri |
| 3 | Discovery | `T1087.004` | Account Discovery: Cloud Account | With mailbox access established, the attacker queries the victim's contacts and recent message metadata. OfficeActivity logs show multiple events with Operation='MailItemsAccessed', ClientIP='91.132.147.168', Folder.Path='\\Contacts' and '\\Inbox', LogonType='Owner', ResultStatus='Succeeded', Workload='Exchange', and RecordType=2 (ExchangeItem). The attacker identifies key individuals in accounts payable and an external procurement partner with active SAP purchase order correspondence. |
| 4 | Defense Evasion | `T1564.008` | Hide Artifacts: Email Hiding Rules | To ensure operational stealth, the attacker creates an inbox rule via /v1.0/users/{id}/mailFolders/inbox/messageRules. OfficeActivity captures a single event with Operation='New-InboxRule', RecordType=1 (ExchangeAdmin), ClientIP='91.132.147.168', ResultStatus='Succeeded', and Parameters containing: Name='ITCleanup', MoveToFolder='RSS Feeds', MarkAsRead=True, SubjectContainsWords='payment;invoice;SAP;purchase order'. This T1564.008 technique prevents the legitimate owner from seeing replies or bounce-backs. |
| 5 | Impact | `T1534` | Internal Spearphishing | The attacker crafts and sends a BEC wire fraud email. OfficeActivity logs Operation='Send', ClientIP='91.132.147.168', Workload='Exchange', ResultStatus='Succeeded', RecordType=2, and Subject='PO-2026-04871 Payment Update - Revised Banking Details'. The message targets the external procurement partner, requesting urgent wire transfer redirection to a fraudulent bank account using established SAP purchase order context (T1534, Impact tactic). |
| 6 | Collection | `T1213` | Data from Information Repositories | In the final stage, the attacker leverages Azure AD SSO to access the SAP web application. AADSignInLogs show a new entry with AppDisplayName='SAP Procurement Portal', ResultType='0', IPAddress='91.132.147.168', and IsInteractive=true. AppServiceHTTPLogs then capture 5-15 GET requests with CIp='91.132.147.168', CsHost='sap-procurement.contoso.azurewebsites.net', CsUriStem values including '/api/finance/vendor-payments', '/api/procurement/purchase-orders', and '/api/finance/ap-ledger', all returning ScStatus=200 with elevated ScBytes (>50KB per response). This T1213 collection completes the dua |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1017` | User Training | T1534 (Internal Spearphishing) | Train users to recognise internal phishing and suspicious OAuth prompts. |
| `M1018` | User Account Management | T1078.004 (Valid Accounts: Cloud Accounts), T1087.004 (Account Discovery: Cloud Account) | Audit cloud account roles, remove standing privileges, and disable unused service principals. |
| `M1026` | Privileged Account Management | T1078.004 (Valid Accounts: Cloud Accounts) | Use Privileged Identity Management (PIM) just-in-time access for high-value cloud roles. |
| `M1027` | Password Policies | T1078.004 (Valid Accounts: Cloud Accounts) | Enforce strong, rotated credentials and disable inactive / stale accounts. |
| `M1031` | Network Intrusion Prevention | T1534 (Internal Spearphishing) | Inspect internal email and chat for known phishing artifacts. |
| `M1032` | Multi-factor Authentication | T1078.004 (Valid Accounts: Cloud Accounts) | Require MFA / Conditional Access on every cloud sign-in, including service principals where supported. |
| `M1047` | Audit | T1087.004 (Account Discovery: Cloud Account) | Alert on bulk user / SP enumeration via Graph. |
