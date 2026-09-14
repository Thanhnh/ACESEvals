"""Detection rules for MDATP alert engine.

Each rule is a dict with:
  - id: unique rule identifier
  - name: alert title
  - severity: Critical / High / Medium / Low / Informational
  - category: MITRE ATT&CK tactic category
  - mitre: MITRE technique ID
  - match: callable(event) -> bool
"""


def _cmd_contains(event, *terms):
    """Check if ProcessCommandLine contains any of the given terms (case-insensitive)."""
    cmd = event.get("ProcessCommandLine", "").lower()
    return any(t in cmd for t in terms)


def _filename_is(event, *names):
    """Check if FileName matches any of the given names (case-insensitive)."""
    fn = event.get("FileName", "").lower()
    return fn in [n.lower() for n in names]


RULES = [
    {
        "id": "MDATP-001",
        "name": "Mimikatz credential theft tool",
        "severity": "High",
        "category": "CredentialAccess",
        "mitre": "T1003.001",
        "match": lambda e: (
            _filename_is(e, "mimikatz.exe")
            or _cmd_contains(e, "sekurlsa::", "lsadump::")
        ),
    },
    {
        "id": "MDATP-002",
        "name": "Kerberoasting activity detected",
        "severity": "High",
        "category": "CredentialAccess",
        "mitre": "T1558.003",
        "match": lambda e: (
            _filename_is(e, "rubeus.exe")
            or _cmd_contains(e, "kerberoast", "asreproast")
        ),
    },
    {
        "id": "MDATP-003",
        "name": "ASEP registry persistence",
        "severity": "Medium",
        "category": "Persistence",
        "mitre": "T1547.001",
        "match": lambda e: (
            e.get("ActionType") == "RegistryValueSet"
            and any(k in e.get("RegistryKey", "").lower()
                    for k in ["\\run\\", "\\runonce\\", "\\services\\"])
        ),
    },
    {
        "id": "MDATP-004",
        "name": "Suspicious scheduled task creation",
        "severity": "Medium",
        "category": "Persistence",
        "mitre": "T1053.005",
        "match": lambda e: (
            _filename_is(e, "schtasks.exe")
            and _cmd_contains(e, "/create")
        ),
    },
    {
        "id": "MDATP-005",
        "name": "Suspected DCSync attack",
        "severity": "Critical",
        "category": "CredentialAccess",
        "mitre": "T1003.006",
        "match": lambda e: e.get("_event_type") == "dcsync" or e.get("_alert") == "dcsync",
    },
    {
        "id": "MDATP-006",
        "name": "Process injection detected",
        "severity": "High",
        "category": "DefenseEvasion",
        "mitre": "T1055",
        "match": lambda e: e.get("ActionType") == "ProcessInjected",
    },
    {
        "id": "MDATP-007",
        "name": "Shadow copy deletion (backup tampering)",
        "severity": "High",
        "category": "Impact",
        "mitre": "T1490",
        "match": lambda e: _cmd_contains(e, "vssadmin", "delete shadows"),
    },
    {
        "id": "MDATP-008",
        "name": "Ransomware behavior detected",
        "severity": "Critical",
        "category": "Impact",
        "mitre": "T1486",
        "match": lambda e: (
            e.get("ActionType") == "FileRenamed"
            and any(ext in e.get("FileName", "").lower()
                    for ext in [".lockbit", ".encrypted", ".ransom", ".crypt"])
        ),
    },
    {
        "id": "MDATP-009",
        "name": "Windows Defender AV disabled",
        "severity": "High",
        "category": "DefenseEvasion",
        "mitre": "T1562.001",
        "match": lambda e: _cmd_contains(e, "set-mppreference", "disablerealtimemonitoring"),
    },
    {
        "id": "MDATP-010",
        "name": "C2 beacon from unexpected process",
        "severity": "Medium",
        "category": "CommandAndControl",
        "mitre": "T1071",
        "match": lambda e: (
            e.get("ActionType") == "ConnectionSuccess"
            and e.get("InitiatingProcessFileName", "").lower()
            in ("notepad.exe", "calc.exe", "mspaint.exe", "wordpad.exe")
        ),
    },
    {
        "id": "MDATP-011",
        "name": "NTDS.dit access detected",
        "severity": "High",
        "category": "CredentialAccess",
        "mitre": "T1003.003",
        "match": lambda e: (
            _cmd_contains(e, "ntdsutil")
            or e.get("_event_type") == "ntds_dump"
        ),
    },
    {
        "id": "MDATP-012",
        "name": "Suspicious LSASS memory access",
        "severity": "High",
        "category": "CredentialAccess",
        "mitre": "T1003.001",
        "match": lambda e: e.get("_event_type") == "lsass_dump",
    },
    {
        "id": "MDATP-013",
        "name": "Primary Refresh Token theft",
        "severity": "High",
        "category": "CredentialAccess",
        "mitre": "T1528",
        "match": lambda e: _cmd_contains(e, "userprttoken", "roadtx", "prt"),
    },
    {
        "id": "MDATP-014",
        "name": "Hands-on-keyboard lateral movement (PsExec)",
        "severity": "High",
        "category": "LateralMovement",
        "mitre": "T1570",
        "match": lambda e: (
            e.get("_event_type") == "psexec_service"
            or (_filename_is(e, "psexec.exe", "psexesvc.exe"))
        ),
    },
    {
        "id": "MDATP-015",
        "name": "ADFS DKM key access",
        "severity": "Critical",
        "category": "CredentialAccess",
        "mitre": "T1552.004",
        "match": lambda e: e.get("_event_type") == "adfs_dkm_access",
    },
    {
        "id": "MDATP-016",
        "name": "Unusual credential addition to OAuth application",
        "severity": "High",
        "category": "Persistence",
        "mitre": "T1098.001",
        "match": lambda e: e.get("_event_type") == "oauth_credential_add",
    },
    {
        "id": "MDATP-017",
        "name": "SID history injection",
        "severity": "Critical",
        "category": "PrivilegeEscalation",
        "mitre": "T1134.005",
        "match": lambda e: e.get("_alert") == "sid_history_injection",
    },
    {
        "id": "MDATP-018",
        "name": "Password spray attack",
        "severity": "Medium",
        "category": "CredentialAccess",
        "mitre": "T1110.003",
        "match": lambda e: e.get("_event_type") == "password_spray",
    },
    {
        "id": "MDATP-019",
        "name": "Boot configuration tampering (bcdedit)",
        "severity": "High",
        "category": "Impact",
        "mitre": "T1490",
        "match": lambda e: _cmd_contains(e, "bcdedit", "recoveryenabled"),
    },
    {
        "id": "MDATP-020",
        "name": "Suspicious service installation",
        "severity": "Medium",
        "category": "Persistence",
        "mitre": "T1543.003",
        "match": lambda e: (
            _filename_is(e, "sc.exe")
            and _cmd_contains(e, "create")
        ),
    },
]
