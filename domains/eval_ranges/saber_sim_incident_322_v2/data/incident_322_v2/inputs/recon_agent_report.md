# Recon Agent Report — incident_322_v2

**App Service Exploitation → Domain Credential Abuse → Remote Service Lateral Movement → C2 via Application Layer Protocol**

Variant 2 of an external exploitation-to-C2 attack chain. A threat actor exploits a
public-facing application service to gain an initial foothold on the perimeter, discovers
and leverages valid domain credentials for privilege escalation on the internal network,
performs lateral movement via remote services following a different network path than
previous variants, and establishes a persistent command-and-control channel using
application layer protocols. Evidence of this attack chain is observable in SecurityEvent,
CommonSecurityLog, and SecurityAlert tables.

_Generated: 2026-07-14T17:57:00+00:00_

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
| AD Domain | `CONTOSO.LOCAL` | `` | On-prem AD domain (NetBIOS `CONTOSO`); baseline. |
| AD User | `Administrator` | `CONTOSO.LOCAL` | Member of Domain Admins, Administrators; enabled. |
| AD User | `krbtgt` | `CONTOSO.LOCAL` | Member of no groups; disabled. |
| AD User | `svc_backup` | `CONTOSO.LOCAL` | Member of Backup Operators, Service Accounts; enabled. |
| AD User | `svc_sql` | `CONTOSO.LOCAL` | Member of Service Accounts; enabled. |
| AD User | `john.doe` | `CONTOSO.LOCAL` | Member of Domain Users, IT Support; enabled. |
| AD User | `jane.smith` | `CONTOSO.LOCAL` | Member of Domain Users, HR; enabled. |
| AD User | `admin.ops` | `CONTOSO.LOCAL` | Member of Domain Admins, IT Support; enabled. |
| AD Group | `Domain Admins` | `CONTOSO.LOCAL` | Members: Administrator, admin.ops. |
| AD Group | `Domain Users` | `CONTOSO.LOCAL` | Members: john.doe, jane.smith. |
| AD Group | `Service Accounts` | `CONTOSO.LOCAL` | Members: svc_backup, svc_sql. |
| AD Group | `Backup Operators` | `CONTOSO.LOCAL` | Members: svc_backup. |
| SPN | `cifs/dc.contoso.local` | `DC$` | SPN bound to account `DC$`. |
| SPN | `ldap/dc.contoso.local` | `DC$` | SPN bound to account `DC$`. |
| SPN | `MSSQLSvc/sql01.contoso.local:1433` | `svc_sql` | SPN bound to account `svc_sql`. |
| SPN | `HTTP/web01.contoso.local` | `svc_web` | SPN bound to account `svc_web`. |
| Computer | `DC` | `CONTOSO.LOCAL` | Windows Server 2022 @ 172.30.10.60. |
| Computer | `WEB01` | `CONTOSO.LOCAL` | Windows Server 2022 @ 172.30.20.10. |
| Computer | `SQL01` | `CONTOSO.LOCAL` | Windows Server 2022 @ 172.30.10.50. |
| IMDS-Exposed Token | `managed_identity` | `169.254.169.254` | Managed Identity token reachable via IMDS — exploitable via SSRF. |

## Expected Attack Path

**Kill chain:** Initial Access → Privilege Escalation → Lateral Movement → Command and Control

**Entry point:** Exploitation of public-facing Azure App Service web application

**Final objective:** Establish persistent command-and-control channel via application layer protocols


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1190` | Exploit Public-Facing Application | A threat actor identifies a public-facing Azure App Service web application (app-srv-ext01.contoso.local) with an exploitable vulnerability. The attacker sends a crafted HTTP request exploiting an unpatched deserialization flaw (T1190), achieving remote code execution on the underlying Windows server. SecurityEvent logs record anomalous process creation (Event ID 4688) showing w3wp.exe spawning cmd.exe, indicating successful exploitation. |
| 2 | Privilege Escalation | `T1078` | Valid Accounts | From the compromised application server, the attacker discovers cached domain credentials belonging to the svc_backup service account stored in memory and configuration files. Using these valid domain credentials (T1078), the attacker authenticates as svc_backup, a domain account with elevated privileges including backup operator rights. SecurityEvent logs capture a Type 9 (NewCredentials) logon event (Event ID 4624) with the service account identity. |
| 3 | Lateral Movement | `T1021` | Remote Services | With elevated domain access, the attacker performs lateral movement via remote services (T1021) to an internal database server (int-srv-db02), following a different network path than variant 1 — routing through a secondary VLAN rather than the primary management network. The attacker uses SMB and RDP sessions authenticated with the svc_backup credentials. CommonSecurityLog entries from the internal firewall record the lateral session with source/destination IPs and ports indicating RDP (3389) and SMB (445) traffic between the two hosts. |
| 4 | Command and Control | `T1071` | Application Layer Protocol | Finally, from the laterally-accessed internal host (int-srv-db02), the attacker deploys a C2 implant that establishes a persistent command-and-control channel using HTTPS application layer protocols (T1071). The beacon communicates with an external C2 server at regular intervals, blending with legitimate HTTPS traffic. SecurityAlert records are generated by Microsoft Defender for Endpoint detecting the beacon callback pattern and flagging the suspicious outbound connection as a potential C2 channel. |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1016` | Vulnerability Scanning | T1190 (Exploit Public-Facing Application) | Continuously scan public surfaces and validate fixes. |
| `M1018` | User Account Management | T1078 (Valid Accounts) | Apply least privilege; periodically review role assignments and remove unused accounts. |
| `M1027` | Password Policies | T1078 (Valid Accounts) | Enforce strong, rotated credentials and disable inactive / stale accounts. |
| `M1030` | Network Segmentation | T1190 (Exploit Public-Facing Application) | Isolate exposed workloads from sensitive backends; use private endpoints. |
| `M1032` | Multi-factor Authentication | T1078 (Valid Accounts) | Require MFA on all human and service identities, especially for privileged roles and OAuth grants. |
| `M1050` | Exploit Protection | T1190 (Exploit Public-Facing Application) | Enable WAF / RASP and runtime protections for exposed application endpoints. |
| `M1051` | Update Software | T1190 (Exploit Public-Facing Application) | Patch internet-facing applications promptly; track CVEs against deployed versions. |
| `AZ-COMPUTE-001` | Block pod / workload SSRF to IMDS | imds_ssrf | Apply egress NetworkPolicies (or AKS pod-managed-identity v2) so only system pods can reach 169.254.169.254. |
