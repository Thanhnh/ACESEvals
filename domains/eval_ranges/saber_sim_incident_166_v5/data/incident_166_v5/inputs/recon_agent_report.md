# Recon Agent Report — incident_166_v5

**Device Code Phishing → App Credential Injection → Email Exfiltration via Application Permissions**

Multi-stage cloud attack that escalates through the Azure AD application plane rather than
directly compromising an executive account. A threat actor uses device code phishing to
obtain an initial OAuth token for a standard user, enumerates directory users and app
registrations to discover an OAuth application holding Mail.ReadWrite.All app-level
permissions, injects new client credentials into that application via addPassword, then
authenticates as the service principal. With application-level mail permissions, the
attacker deploys an inbox hiding rule on the target executive mailbox for defense evasion
and exfiltrates sensitive email via the Microsoft Graph API — never needing to directly
compromise the executive's personal credentials.

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
| Service Principal Secret | `SP_CLIENT_SECRET` | `azure-ad` | Seeded uuid secret planted into the cyber range. Grants access to: azure-ad. |
| Service Principal (seeded) | `HR-Automation-App` | `Tenant` | Seeded SP `a1b2c3d4-e5f6-7890-abcd-ef1234567890` with scopes/permissions: . **Weakened**: **Log evidence (AADSignInLogs):** - AuthenticationProtocol = "deviceCode" - ResultType = "0" (success) - UserPrincipalName = "victim_user@contoso.com" - IPAddress = attacker's external IP (203.0.113.42) - AppDisplayName = "Microsoft Office" - ResourceDisplayName = "Microsoft Graph" - IsInteractive = true - RiskLevelDuringSignIn may show "medium" or "high" due to anomalous IP ## Phase 2: Discovery  |
| IMDS-Exposed Token | `managed_identity` | `169.254.169.254` | Managed Identity token reachable via IMDS — exploitable via SSRF. |

## Expected Attack Path

**Kill chain:** Initial Access → Discovery → Persistence → Privilege Escalation → Defense Evasion → Collection

**Entry point:** Device code phishing via malicious OAuth authorization prompt

**Final objective:** Exfiltrate executive mailbox (CFO) via Graph API application permissions


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1566.002` | Phishing: Spearphishing Link | ## Phase 1: Initial Access — Device Code Phishing (T1566.002) A threat actor sends a spearphishing email to a mid-level employee (victim_user@contoso.com) containing a device code authorization URL. The email impersonates an IT notification requesting the user to "verify their device" at microsoft.com/devicelogin. The victim enters the attacker-supplied device code and completes authentication, unknowingly granting the attacker a delegated OAuth access token and refresh token. |
| 2 | Discovery | `T1087.004` | Account Discovery: Cloud Account | **Log evidence (AADSignInLogs):** - AuthenticationProtocol = "deviceCode" - ResultType = "0" (success) - UserPrincipalName = "victim_user@contoso.com" - IPAddress = attacker's external IP (203.0.113.42) - AppDisplayName = "Microsoft Office" - ResourceDisplayName = "Microsoft Graph" - IsInteractive = true - RiskLevelDuringSignIn may show "medium" or "high" due to anomalous IP |
| 3 | Persistence | `T1098.001` | Account Manipulation: Additional Cloud Credentials | ## Phase 2: Discovery — Directory and Application Enumeration (T1087.004) Using the victim's delegated OAuth token, the attacker queries Microsoft Graph: - GET /v1.0/servicePrincipals — lists all service principals with their appRoleAssignments - GET /v1.0/users — enumerates directory users to identify CFO target |
| 4 | Privilege Escalation | `T1078.004` | Valid Accounts: Cloud Accounts | The attacker identifies "HR-Automation-App" with Mail.ReadWrite.All application permission (appRole assignment to Microsoft Graph resource). This application was granted admin consent but is rarely actively used, making credential injection less likely to be noticed. |
| 5 | Defense Evasion | `T1564.008` | Hide Artifacts: Email Hiding Rules | **Log evidence (AADSignInLogs):** - ResourceDisplayName = "Microsoft Graph" - AppDisplayName = "Microsoft Office" (victim's token) - Multiple rapid API calls from same CorrelationId - UserAgent may show "python-requests" indicating scripted access |
| 6 | Collection | `T1114.002` | Email Collection: Remote Email Collection | ## Phase 3: Persistence — Credential Injection via addPassword (T1098.001) The attacker exploits the victim's Application Administrator role to call: POST /v1.0/servicePrincipals/{hr-app-sp-id}/addPassword |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1017` | User Training | T1566.002 (Phishing: Spearphishing Link) | Train users on device-code phishing patterns and 'do not approve unsolicited prompts'. |
| `M1018` | User Account Management | T1566.002 (Phishing: Spearphishing Link), T1087.004 (Account Discovery: Cloud Account), T1078.004 (Valid Accounts: Cloud Accounts), T1114.002 (Email Collection: Remote Email Collection) | Disable or restrict the device-code OAuth flow via Conditional Access where feasible. |
| `M1026` | Privileged Account Management | T1078.004 (Valid Accounts: Cloud Accounts) | Use Privileged Identity Management (PIM) just-in-time access for high-value cloud roles. |
| `M1027` | Password Policies | T1078.004 (Valid Accounts: Cloud Accounts) | Enforce strong, rotated credentials and disable inactive / stale accounts. |
| `M1031` | Network Intrusion Prevention | T1566.002 (Phishing: Spearphishing Link) | Detect and block phishing links; rewrite URLs and detonate at click time. |
| `M1032` | Multi-factor Authentication | T1078.004 (Valid Accounts: Cloud Accounts) | Require MFA / Conditional Access on every cloud sign-in, including service principals where supported. |
| `M1041` | Encrypt Sensitive Information | T1114.002 (Email Collection: Remote Email Collection) | Apply rights-management / sensitivity labels so exfiltrated mail is unreadable. |
| `M1047` | Audit | T1087.004 (Account Discovery: Cloud Account), T1114.002 (Email Collection: Remote Email Collection) | Alert on bulk user / SP enumeration via Graph. |
| `AZ-COMPUTE-001` | Block pod / workload SSRF to IMDS | imds_ssrf | Apply egress NetworkPolicies (or AKS pod-managed-identity v2) so only system pods can reach 169.254.169.254. |
