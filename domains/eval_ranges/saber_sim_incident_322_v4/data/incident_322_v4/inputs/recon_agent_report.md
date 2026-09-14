# Recon Agent Report — incident_322_v4

**App Service Exploitation → C2 Beacon → LSASS Credential Dump → WMI Lateral Movement**

Variant 4 of an external exploitation-to-C2 attack chain. A threat actor exploits a
public-facing web application hosted on Azure App Service to gain initial code execution
on the underlying Windows host. The attacker establishes a persistent HTTP-based
command-and-control channel, then discovers and dumps domain credentials from LSASS
memory for privilege escalation. Finally, the attacker pivots laterally to a secondary
internal workstation via WMI remote execution, demonstrating an alternate lateral
movement path. Evidence surfaces across SecurityEvent (Windows host logon/process
events), CommonSecurityLog (network device C2 traffic detection), and SecurityAlert
(detection engine alerts) tables.

_Generated: 2026-07-15T19:11:41+00:00_

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
| AD Domain | `CORPNET.LOCAL` | `` | On-prem AD domain (NetBIOS `CORPNET`); baseline. |
| AD User | `Administrator` | `CORPNET.LOCAL` | Member of Domain Admins, Administrators; enabled. |
| AD User | `krbtgt` | `CORPNET.LOCAL` | Member of no groups; disabled. |
| AD User | `svc_backup` | `CORPNET.LOCAL` | Member of Backup Operators, Service Accounts; enabled. |
| AD User | `svc_sql` | `CORPNET.LOCAL` | Member of Service Accounts; enabled. |
| AD User | `john.doe` | `CORPNET.LOCAL` | Member of Domain Users, IT Support; enabled. |
| AD User | `jane.smith` | `CORPNET.LOCAL` | Member of Domain Users, HR; enabled. |
| AD User | `admin.ops` | `CORPNET.LOCAL` | Member of Domain Admins, IT Support; enabled. |
| AD Group | `Domain Admins` | `CORPNET.LOCAL` | Members: Administrator, admin.ops. |
| AD Group | `Domain Users` | `CORPNET.LOCAL` | Members: john.doe, jane.smith. |
| AD Group | `Service Accounts` | `CORPNET.LOCAL` | Members: svc_backup, svc_sql. |
| AD Group | `Backup Operators` | `CORPNET.LOCAL` | Members: svc_backup. |
| SPN | `cifs/dc.corpnet.local` | `DC$` | SPN bound to account `DC$`. |
| SPN | `ldap/dc.corpnet.local` | `DC$` | SPN bound to account `DC$`. |
| SPN | `MSSQLSvc/sql01.corpnet.local:1433` | `svc_sql` | SPN bound to account `svc_sql`. |
| SPN | `HTTP/web01.corpnet.local` | `svc_web` | SPN bound to account `svc_web`. |
| Computer | `DC` | `CORPNET.LOCAL` | Windows Server 2022 @ 172.30.10.60. |
| Computer | `WEB01` | `CORPNET.LOCAL` | Windows Server 2022 @ 172.30.20.10. |
| Computer | `SQL01` | `CORPNET.LOCAL` | Windows Server 2022 @ 172.30.10.50. |

## Expected Attack Path

**Kill chain:** Initial Access → Command and Control → Credential Access → Lateral Movement

**Entry point:** Remote code execution exploit against public-facing Azure App Service web application

**Final objective:** Lateral movement to secondary internal workstation via WMI using stolen domain credentials


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1190` | Exploit Public-Facing Application | A threat actor identifies a public-facing web application running on Azure App Service (app-host-01.corpnet.local). The application contains a remote code execution vulnerability that allows arbitrary command execution on the underlying Windows host. |
| 2 | Command and Control | `T1071.001` | Application Layer Protocol: Web Protocols | Phase 1 - Initial Access (T1190): The attacker crafts a malicious HTTP request exploiting the web application vulnerability, achieving code execution on the Windows server hosting the App Service. SecurityEvent logs record the anomalous child process spawned by the w3wp.exe worker process (e.g., cmd.exe or powershell.exe spawning under w3wp.exe with EventID 4688). Key evidence: Process creation with ParentProcessName=w3wp.exe and suspicious CommandLine arguments on Computer=app-host-01. |
| 3 | Credential Access | `T1003.001` | OS Credential Dumping: LSASS Memory | Phase 2 - Command and Control (T1071.001): With shell access established, the attacker deploys an HTTP-based C2 implant that beacons out to attacker infrastructure over standard HTTPS port 443, blending with legitimate web traffic. The persistent beacon registers with the C2 framework and begins periodic check-ins. CommonSecurityLog entries from the network perimeter device (firewall/proxy) capture the anomalous outbound HTTP sessions with characteristic beacon timing patterns. Key evidence: DeviceAction=Allow, DestinationPort=443, periodic SentBytes/ReceivedBytes patterns with consistent inte |
| 4 | Lateral Movement | `T1047` | Windows Management Instrumentation | Phase 3 - Credential Access (T1003.001): Operating through the C2 channel, the attacker enumerates running processes, discovers the LSASS process, and performs an in-memory credential dump extracting cached domain credentials (NTLM hashes and Kerberos tickets) for the CORPNET.LOCAL domain. The credential access triggers a SecurityAlert from Microsoft Defender for Endpoint with AlertName="Suspicious LSASS memory access" and Techniques=T1003.001. Key evidence: SecurityAlert with CompromisedEntity=app-host-01, AlertSeverity=High, Tactics=CredentialAccess. |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1016` | Vulnerability Scanning | T1190 (Exploit Public-Facing Application) | Continuously scan public surfaces and validate fixes. |
| `M1030` | Network Segmentation | T1190 (Exploit Public-Facing Application) | Isolate exposed workloads from sensitive backends; use private endpoints. |
| `M1031` | Network Intrusion Prevention | T1071.001 (Application Layer Protocol: Web Protocols) | Inspect HTTPS egress with TLS interception or DNS / SNI based blocking. |
| `M1037` | Filter Network Traffic | T1071.001 (Application Layer Protocol: Web Protocols) | Restrict egress to allow-listed FQDNs and alert on anomalous beacons. |
| `M1050` | Exploit Protection | T1190 (Exploit Public-Facing Application) | Enable WAF / RASP and runtime protections for exposed application endpoints. |
| `M1051` | Update Software | T1190 (Exploit Public-Facing Application) | Patch internet-facing applications promptly; track CVEs against deployed versions. |
