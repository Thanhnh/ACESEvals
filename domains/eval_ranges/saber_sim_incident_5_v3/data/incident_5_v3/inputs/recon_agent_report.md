# Recon Agent Report — incident_5_v3

**Spearphishing Macro → Process Injection → LSASS Dump → WMI Lateral Movement → DCSync Domain Dominance**

Multi-stage endpoint attack beginning with a spearphishing attachment delivering a malicious
Word document (WINWORD.EXE with embedded VBA macro). Upon macro execution, the payload
performs process injection into svchost.exe to evade EDR detection. The injected process
dumps LSASS memory to harvest domain credentials. Variant 3 uses WMI-based lateral movement
to reach the domain controller, where DCSync replication extracts the full domain credential
set achieving complete domain dominance.

_Generated: 2026-07-15T19:11:40+00:00_

## Entity Inventory

| Resource Type | Name | Parent Resource | Description |
|---|---|---|---|
| Subscription | `SABER-Sim Subscription` | `` | Subscription `12345678-1234-1234-1234-123456789abc` in tenant `87654321-4321-4321-4321-cba987654321`; baseline. |
| Tenant | `87654321-4321-4321-4321-cba987654321` | `SABER-Sim Subscription` | Azure AD tenant; baseline. |
| Resource Group | `production-rg` | `SABER-Sim Subscription` | Resource group in `eastus`; baseline. |
| Resource Group | `development-rg` | `SABER-Sim Subscription` | Resource group in `eastus`; baseline. |
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

## Expected Attack Path

**Kill chain:** Initial Access → Defense Evasion → Credential Access → Lateral Movement → Credential Access

**Entry point:** Spearphishing attachment delivering malicious Word document with VBA macro

**Final objective:** DCSync replication to extract full domain credential set for domain dominance


| # | Stage | MITRE ID | Technique | Description |
|---|---|---|---|---|
| 1 | Initial Access | `T1566.001` | Phishing: Spearphishing Attachment | Phase 1 — Initial Access (T1566.001): A threat actor crafts a spearphishing email targeting user jsmith@contoso.local with a malicious Word document attachment disguised as a quarterly financial report. When the victim opens the document on workstation wkstn01, an embedded VBA macro executes, launching a child process from WINWORD.EXE. DeviceProcessEvents logs capture the suspicious process lineage (WINWORD.EXE → cmd.exe → payload.exe). |
| 2 | Defense Evasion | `T1055` | Process Injection | Phase 2 — Defense Evasion (T1055): The initial payload performs process injection into svchost.exe, a legitimate Windows system process with hundreds of instances running at any time. By injecting into this trusted process, the attacker evades EDR behavioral rules that monitor untrusted executables. DeviceProcessEvents captures the cross-process memory write via CreateRemoteThread API call targeting svchost.exe PID. |
| 3 | Credential Access | `T1003.001` | OS Credential Dumping: LSASS Memory | Phase 3 — Credential Access (T1003.001): Operating within the injected svchost.exe context (running as SYSTEM), the attacker dumps LSASS process memory using MiniDumpWriteDump. The dump yields cached NTLM hashes for domain users authenticated on the workstation, including a domain administrator hash. DeviceProcessEvents logs svchost.exe accessing lsass.exe memory with PROCESS_VM_READ access rights. |
| 4 | Lateral Movement | `T1047` | Windows Management Instrumentation | Phase 4 — Lateral Movement (T1047): Using the harvested domain administrator NTLM hash, the attacker initiates WMI-based lateral movement (Win32_Process.Create via DCOM) to the domain controller dc01. This variant specifically uses WMI rather than PsExec or SMB. LateralMovementEvents records the WMI connection from wkstn01 to dc01 with MovementType=WMI. |
| 5 | Credential Access | `T1003.006` | OS Credential Dumping: DCSync | Phase 5 — Credential Access / Domain Dominance (T1003.006): With administrative access on the domain controller, the attacker executes DCSync — using the Directory Replication Service (DRS) protocol to request replication of credential data. The DRS GetNCChanges call extracts NTLM hashes for every domain account including KRBTGT (enabling Golden Ticket attacks). WindowsSecurityEvents on dc01 logs Event ID 4662 with DS-Replication-Get-Changes extended right access to the domain naming context DC=contoso,DC=local. |

## Recommended Mitigations

| ID | Mitigation | Applies To | Description |
|---|---|---|---|
| `M1017` | User Training | T1566.001 (Phishing: Spearphishing Attachment) | Train users to identify malicious attachments and report them quickly. |
| `M1021` | Restrict Web-Based Content | T1566.001 (Phishing: Spearphishing Attachment) | Block execution of mounted ISO contents and unsigned executables from email. |
| `M1031` | Network Intrusion Prevention | T1566.001 (Phishing: Spearphishing Attachment) | Detonate inbound attachments in a sandbox; block ISO / LNK / HTA where possible. |
