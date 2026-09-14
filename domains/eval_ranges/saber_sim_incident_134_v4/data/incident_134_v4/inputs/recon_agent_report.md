# Recon Agent Report — incident_134_v4

**OAuth Redirect Phishing → Internal Spearphish → Inbox Hiding → BEC Wire Fraud**

Business Email Compromise attack initiated through an OAuth redirect phishing campaign
targeting Azure AD credentials. The threat actor crafts a malicious OAuth authorization
URL with a manipulated redirect_uri to harvest an initial victim's authorization code.
After authenticating as the initial victim, the attacker leverages that user's trusted
internal identity to send an internal spearphishing email to a finance executive. Once
the executive's credentials are captured via the same OAuth redirect technique, the
attacker creates inbox rules to suppress reply notifications and hide evidence of the
compromise, then sends fraudulent wire transfer requests to finance team members from
the compromised executive email account. Variant 4 uses OAuth redirect abuse as the
initial access vector and leverages internal spearphishing as the lateral movement
path to reach BEC objectives.

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

**Kill chain:** Initial Access → Lateral Movement → Credential Access → Defense Evasion → Impact

**Entry point:** OAuth redirect abuse via crafted authorization URL with malicious redirect_uri

**Final objective:** Business Email Compromise — fraudulent wire transfer requests from executive mailbox


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1566.002` | Phishing: Spearphishing Link | Phase 1 — Initial Access (T1566.002): A threat actor crafts a malicious OAuth authorization URL targeting the organization's Azure AD tenant at GET /<tenant_id>/oauth2/v2.0/authorize with a legitimate client_id but a redirect_uri pointing to the attacker's controlled server. The phishing link is distributed via an external email campaign to a mid-level employee. When the victim clicks the link and authenticates at Azure AD, their authorization code is redirected to the attacker's endpoint. The attacker exchanges this code at POST /<tenant_id>/oauth2/v2.0/token (grant_type=authorization_code, c |
| 2 | Lateral Movement | `T1534` | Internal Spearphishing | Detection evidence in AADSignInLogs:   TimeGenerated=2026-06-01T09:14:22Z, OperationName="Sign-in activity",   Category="SignInLogs", ResultType="0", ResultDescription="Success",   UserPrincipalName="m.johnson@contoso.com", UserDisplayName="Marcus Johnson",   UserId="aaa11111-bb22-cc33-dd44-eee555666777",   AppDisplayName="HR Benefits Portal",   AppId="e4f5a6b7-c8d9-0e1f-2a3b-4c5d6e7f8a9b", IPAddress="185.220.101.42",   Location="RO", ClientAppUsed="Browser", IsInteractive=true,   ResourceDisplayName="Microsoft Graph",   ResourceId="00000003-0000-0000-c000-000000000000",   AuthenticationRequir |
| 3 | Credential Access | `T1078.004` | Valid Accounts: Cloud Accounts | Phase 2 — Lateral Movement (T1534): Using the initial victim's OAuth token (INITIAL_USER_TOKEN), the attacker calls POST /v1.0/users/m.johnson@contoso.com/sendMail to send an internal spearphishing email to the CFO (finance executive s.patel@contoso.com). The email contains an identical OAuth redirect link themed as an internal document approval request. Because the email originates from a trusted internal colleague, it bypasses external mail filtering. |
| 4 | Defense Evasion | `T1564.008` | Hide Artifacts: Email Hiding Rules | Detection evidence in OfficeActivity:   CreationTime="2026-06-01T09:18:45.123Z",   Id="550e8400-e29b-41d4-a716-446655440001",   Operation="Send", OrganizationId="87654321-4321-4321-4321-cba987654321",   RecordType=2, RecordTypeName="ExchangeItem", ResultStatus="Succeeded",   UserKey="m.johnson@contoso.com", UserId="m.johnson@contoso.com", UserType=0,   Workload="Exchange", ClientIP="185.220.101.42",   ClientIPAddress="185.220.101.42",   ClientInfoString="Client=REST;Action=SendMail",   MailboxOwnerUPN="m.johnson@contoso.com",   Subject="Action Required: Q2 Budget Approval Link",   InternetMess |
| 5 | Impact | `T1534` | Internal Spearphishing | Phase 3 — Credential Access (T1078.004): The finance executive (CFO, s.patel@contoso.com) clicks the internal phishing link and authenticates at Azure AD. The authorization code is redirected to the attacker's endpoint. The attacker exchanges this code for an OAuth token (EXEC_OAUTH_TOKEN) with Mail.ReadWrite and Mail.Send scopes for the executive. |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1017` | User Training | T1566.002 (Phishing: Spearphishing Link), T1534 (Internal Spearphishing) | Train users on device-code phishing patterns and 'do not approve unsolicited prompts'. |
| `M1018` | User Account Management | T1566.002 (Phishing: Spearphishing Link), T1078.004 (Valid Accounts: Cloud Accounts) | Disable or restrict the device-code OAuth flow via Conditional Access where feasible. |
| `M1026` | Privileged Account Management | T1078.004 (Valid Accounts: Cloud Accounts) | Use Privileged Identity Management (PIM) just-in-time access for high-value cloud roles. |
| `M1027` | Password Policies | T1078.004 (Valid Accounts: Cloud Accounts) | Enforce strong, rotated credentials and disable inactive / stale accounts. |
| `M1031` | Network Intrusion Prevention | T1566.002 (Phishing: Spearphishing Link), T1534 (Internal Spearphishing) | Detect and block phishing links; rewrite URLs and detonate at click time. |
| `M1032` | Multi-factor Authentication | T1078.004 (Valid Accounts: Cloud Accounts) | Require MFA / Conditional Access on every cloud sign-in, including service principals where supported. |
