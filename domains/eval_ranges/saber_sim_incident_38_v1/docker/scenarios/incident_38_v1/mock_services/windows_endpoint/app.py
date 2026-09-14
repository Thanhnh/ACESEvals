"""Windows Endpoint mock service for SABER-SIM.

Simulates a Windows workstation/server with MDE (Microsoft Defender for
Endpoint) telemetry.  All endpoint interactions are high-level semantic
actions designed to be Proxmox-upgrade-ready (Phase 6).

Endpoints:
  POST /process/execute           — spawn a process
  POST /process/inject/{pid}      — process injection
  POST /file/create               — drop a file
  POST /file/modify               — modify/rename a file
  DELETE /file/{path}             — delete a file
  POST /registry/write            — write registry key
  GET  /registry/read/{key_path}  — read registry value
  POST /scheduled-task/create     — create scheduled task
  POST /service/create            — install Windows service
  POST /network/connect           — outbound connection
  POST /credential/dump-lsass     — LSASS memory dump
  POST /credential/steal-prt      — PRT token theft
  POST /defender/disable          — disable Defender
  POST /vss/delete                — delete shadow copies
  POST /bcdedit/modify            — modify boot config
  GET  /audit/logs                — retrieve accumulated logs
  POST /admin/config              — inject runtime config
"""

from __future__ import annotations

import os
import secrets
import sys
import uuid
from datetime import datetime, timezone

from flask import Flask, request, jsonify

# Allow import of shared MockServiceBase from parent directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from mock_service_base import MockServiceBase, create_base_blueprint

from process_tree import ProcessTree
from log_emitter import MdeLogEmitter

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
base = MockServiceBase("windows-endpoint")
app.register_blueprint(
    create_base_blueprint(
        base,
        health_extras={
            "hostname": os.environ.get("HOSTNAME", "win-endpoint-01"),
            "domain": os.environ.get("DOMAIN", "CONTOSO"),
            "user": os.environ.get("LOGGED_IN_USER", "user"),
            "os": "Windows 10 Enterprise",
        },
    )
)

# ---------------------------------------------------------------------------
# In-memory state
# ---------------------------------------------------------------------------

HOSTNAME = os.environ.get("HOSTNAME", "win-endpoint-01")
DOMAIN = os.environ.get("DOMAIN", "CONTOSO")
DEVICE_ID = os.environ.get("DEVICE_ID", str(uuid.uuid4()))
MACHINE_SID = os.environ.get("MACHINE_SID", f"S-1-5-21-{secrets.randbelow(10**9)}-{secrets.randbelow(10**9)}-{secrets.randbelow(10**9)}")

process_tree = ProcessTree(
    hostname=HOSTNAME,
    domain=DOMAIN,
    device_id=DEVICE_ID,
    machine_sid=MACHINE_SID,
)

emitter = MdeLogEmitter(
    device_id=DEVICE_ID,
    device_name=HOSTNAME,
    domain=DOMAIN,
)

file_system: dict[str, dict] = {}     # full_path -> {hash, size, created_by_pid}
registry: dict[str, dict] = {}        # key\valueName -> {data, type, pid}
lsass_credentials: list[dict] = []    # pre-seeded via /admin/config


# ---------------------------------------------------------------------------
# Command-line tradecraft dispatcher (Phase 10 P5 — live red-team realism)
# ---------------------------------------------------------------------------
#
# A real attacker on a foothost runs OS-native tooling from a shell / C2 beacon;
# the host's EDR derives telemetry from the COMMAND LINE, not from a bespoke REST
# route per technique. This dispatcher lets a single shell-style call
# (``/process/execute`` or ``/shell``) reproduce the rich technique telemetry that
# the legacy semantic routes (``/credential/dump-lsass`` etc.) emit — by matching
# the command line against known tradecraft patterns. The agent supplies REAL
# offensive command lines (its own pretrained knowledge); the mock recognises them
# and stamps the distinctive markers. No range-specific API is leaked.

def _tradecraft_emissions(command_line: str, user: str) -> tuple[str | None, list[dict]]:
    """Classify a command line and return ``(event_type_tag, extra_logs)``.

    ``event_type_tag`` is stamped onto the spawned DeviceProcessEvents row (e.g.
    ``"lsass_dump"`` so the MDATP alert engine raises the SecurityAlert). Each
    entry in ``extra_logs`` is an additional row to append (e.g. SecurityEvent
    4719 / 4698). Patterns are matched case-insensitively against the full command
    line so any equivalent real-world invocation triggers the right signal.
    """
    c = (command_line or "").lower()
    tag: str | None = None
    extras: list[dict] = []

    def has(*subs: str) -> bool:
        return all(s in c for s in subs)

    # T1003.001 — LSASS memory dump (comsvcs MiniDump, procdump, mimikatz,
    # nanodump, direct lsass .dmp). Tagging the process row makes MDATP-012 fire.
    if (has("comsvcs", "minidump") or has("procdump", "lsass")
            or "sekurlsa" in c or "mimikatz" in c or "nanodump" in c
            or has("rundll32", "comsvcs") or has("lsass", ".dmp")
            or "out-minidump" in c):
        tag = "lsass_dump"

    # T1562.001 — defender / AV tampering (Set-MpPreference, sc stop WinDefend,
    # DisableAntiSpyware). Emits SecurityEvent 4719 (audit-policy change marker).
    if (has("set-mppreference", "disablerealtimemonitoring")
            or has("sc", "stop", "windefend")
            or "disableantispyware" in c
            or has("set-mppreference", "disableioavprotection")):
        extras.append(emitter.security_event_audit_policy_change(account_name=user))

    # T1053.005 — scheduled-task persistence (schtasks /create,
    # Register-ScheduledTask). Emits SecurityEvent 4698 (task-created marker).
    if has("schtasks", "/create") or "register-scheduledtask" in c:
        extras.append({
            "TimeGenerated": datetime.now(timezone.utc).isoformat(),
            "Computer": emitter.device_name,
            "EventID": 4698,
            "Activity": "4698 - A scheduled task was created.",
            "Channel": "Security",
            "SubjectUserName": user,
            "TaskName": "\\AttackerTask",
            "TaskContent": command_line,
            "Type": "SecurityEvent",
        })

    return tag, extras


# ---------------------------------------------------------------------------
# Endpoints — Process operations
# ---------------------------------------------------------------------------


@app.route("/process/execute", methods=["POST"])
def process_execute():
    """Spawn a process in the in-memory process tree."""
    data = request.get_json(force=True)
    file_name = data.get("fileName", "unknown.exe")
    command_line = data.get("commandLine", file_name)
    parent_process = data.get("parentProcess")
    user = data.get("user", "SYSTEM")
    sha256 = data.get("sha256")
    folder_path = data.get("folderPath")

    proc = process_tree.spawn(file_name, command_line, parent_process, user, sha256, folder_path)
    parent = process_tree.get_process(proc.parent_pid)

    log = emitter.device_process_event(proc, parent)
    # Command-line tradecraft dispatcher: stamp the technique tag (e.g. LSASS
    # dump → MDATP alert) and emit any extra markers (4719 / 4698) the command
    # line implies, so a single shell-style call yields the full technique
    # telemetry without a bespoke route (Phase 10 P5 live red-team realism).
    _tag, _extras = _tradecraft_emissions(command_line, user)
    if _tag:
        log["_event_type"] = _tag
    base.append_log(log)
    for _ex in _extras:
        base.append_log(_ex)

    return jsonify({
        "processId": proc.pid,
        "parentProcessId": proc.parent_pid,
        "timestamp": proc.timestamp.isoformat() + "Z",
        "status": "created",
    })


def _shell_stdout(cmd: str) -> str:
    """Plausible stdout for common on-host recon/exec commands.

    Gives the red agent realistic feedback so its enumeration is genuine (it
    learns the environment by running real commands, not by reading a script).
    Unknown commands return a generic success line.
    """
    c = (cmd or "").strip()
    low = c.lower()
    dom = DOMAIN
    host = HOSTNAME
    me = os.environ.get("LOGGED_IN_USER", "user")
    if low.startswith("whoami") and "/all" in low:
        return (f"USER INFORMATION\n----------------\nUser Name      SID\n"
                f"{dom}\\{me}   S-1-5-21-1234567890-1234567890-1234567890-1107\n\n"
                f"GROUP INFORMATION\n-----------------\n{dom}\\Domain Users\n"
                f"{dom}\\Workstation Admins\nBUILTIN\\Users")
    if low.startswith("whoami"):
        return f"{dom.lower()}\\{me}"
    if low.startswith("hostname"):
        return host
    if "net user /domain" in low or low.startswith("net user /domain"):
        return (f"User accounts for \\\\{dom}-DC01\n\n"
                "-------------------------------------------------------------\n"
                "Administrator   dadmin          jsmith\n"
                "krbtgt          svc-sql         svc-backup\n"
                "The command completed successfully.")
    if low.startswith("net user"):
        return ("User accounts for \\\\" + host + "\n\n"
                "-------------------------------------------------------------\n"
                f"Administrator   {me}   Guest\nThe command completed successfully.")
    if "net group" in low and "domain admins" in low:
        return ("Group name     Domain Admins\nMembers\n"
                "-------------------------------------------------------------\n"
                "Administrator            dadmin\nThe command completed successfully.")
    if low.startswith("nltest") and "dclist" in low:
        return (f"Get list of DCs in domain '{dom}' from '\\\\{dom}-DC01':\n"
                f"    {dom}-DC01.{dom.lower()}.local [PDC]  [DS] Site: Default-First-Site\n"
                "The command completed successfully")
    if low.startswith("ipconfig"):
        return ("Windows IP Configuration\n\nEthernet adapter Ethernet0:\n"
                "   IPv4 Address. . . . . . . . . . . : 10.0.10.41\n"
                "   Default Gateway . . . . . . . . . : 10.0.10.1")
    if low.startswith("tasklist"):
        return ("Image Name              PID\n========================  ====\n"
                "lsass.exe               624\nsvchost.exe             892\n"
                "explorer.exe           2104")
    return f"[{host}] command executed: {c}"


@app.route("/shell", methods=["POST"])
def shell():
    """Interactive C2 beacon on the compromised host (Phase 10 P5).

    The realistic on-prem attacker interface: the operator holds a beacon/shell on
    a foothost and runs OS-native commands. POST ``{"cmd": "...", "user": "..."}``;
    the host spawns the process (DeviceProcessEvents), applies the command-line
    tradecraft dispatcher (LSASS/defender/schtasks markers), and returns plausible
    stdout. The agent supplies its OWN tradecraft — no range-specific API is
    revealed; it just has a shell, exactly as a real C2 operator would.
    """
    data = request.get_json(force=True)
    cmd = data.get("cmd", data.get("commandLine", ""))
    user = data.get("user", os.environ.get("LOGGED_IN_USER", "user"))
    file_name = (cmd.strip().split() or ["cmd.exe"])[0]

    proc = process_tree.spawn(file_name, cmd, None, user)
    log = emitter.device_process_event(proc)
    _tag, _extras = _tradecraft_emissions(cmd, user)
    if _tag:
        log["_event_type"] = _tag
    base.append_log(log)
    for _ex in _extras:
        base.append_log(_ex)

    return jsonify({
        "host": HOSTNAME,
        "user": user,
        "processId": proc.pid,
        "stdout": _shell_stdout(cmd),
        "status": "executed",
    })


@app.route("/process/inject/<int:target_pid>", methods=["POST"])
def process_inject(target_pid: int):
    """Process injection into a running process."""
    data = request.get_json(force=True)
    source_pid = data.get("sourcePid", 0)
    technique = data.get("technique", "dll_injection")
    user = data.get("user", "SYSTEM")

    source = process_tree.get_process(source_pid)
    target = process_tree.get_process(target_pid)

    if not target:
        return jsonify({"error": f"Target PID {target_pid} not found"}), 404

    injection = process_tree.inject(source_pid, target_pid, technique)

    # Emit injection log
    if source and target:
        log = emitter.process_injection_event(source, target, technique)
        base.append_log(log)

    # Emit image load event (DLL loaded into target)
    img_log = emitter.device_image_load_event(
        file_name=f"{technique}.dll",
        folder_path="C:\\Windows\\System32",
        process_info=target,
    )
    base.append_log(img_log)

    return jsonify({
        "status": "injected",
        "sourcePid": source_pid,
        "targetPid": target_pid,
        "technique": technique,
        "timestamp": injection.timestamp.isoformat() + "Z",
    })


# ---------------------------------------------------------------------------
# Endpoints — Web / IIS exploitation
# ---------------------------------------------------------------------------


@app.route("/web/exploit", methods=["POST"])
def web_exploit():
    """Exploit a public-facing IIS app for code execution (T1190).

    Models the post-exploitation telemetry: the IIS worker process
    (``w3wp.exe``) spawns a command shell that runs recon (``whoami``) — the
    DeviceProcessEvents row whose ProcessCommandLine carries the T1190 marker,
    with ``w3wp.exe`` as the initiating process (the web-exploit signature).
    """
    data = request.get_json(force=True)
    user = data.get("user", "IIS APPPOOL\\DefaultAppPool")
    command = data.get("command", "cmd.exe /c whoami")

    # The IIS worker process is the parent of the spawned shell.
    w3wp = process_tree.spawn("w3wp.exe", "w3wp.exe -ap \"DefaultAppPool\"", None, user)
    child = process_tree.spawn(
        command.split()[0] if command else "cmd.exe",
        command, "w3wp.exe", user,
    )
    base.append_log(emitter.device_process_event(child, w3wp))

    # SecurityEvent 4688 — the Sentinel artifact of the same post-exploit process
    # creation on the web host (on-prem IIS T1190 marker). Flat SecurityEvent
    # shape (top-level EventID); routed by Type.
    base.append_log({
        "TimeGenerated": child.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "Computer": HOSTNAME,
        "EventID": 4688,
        "Activity": "4688 - A new process has been created.",
        "Channel": "Security",
        "NewProcessName": child.file_name,
        "CommandLine": command,
        "ParentProcessName": "w3wp.exe",
        "SubjectUserName": user,
        "Type": "SecurityEvent",
    })

    return jsonify({"status": "exploited", "processId": child.pid, "parentProcessId": w3wp.pid})


@app.route("/web/shell", methods=["POST"])
def web_shell():
    """Deploy an ASPX web shell to the IIS webroot (T1505.003).

    Leaves the two web-shell artifacts: a ``.aspx`` file dropped in the web root
    (DeviceFileEvents, the FileName marker) and the IIS worker (``w3wp.exe``)
    spawning a command interpreter through the shell (DeviceProcessEvents whose
    InitiatingProcessFileName is ``w3wp.exe``).
    """
    data = request.get_json(force=True)
    user = data.get("user", "IIS APPPOOL\\DefaultAppPool")
    shell_name = data.get("fileName", "shell.aspx")
    webroot = data.get("folderPath", "C:\\inetpub\\wwwroot")
    sha256 = data.get("sha256", "")

    # 1. The web shell file written to the web root (w3wp.exe as initiator).
    w3wp = process_tree.spawn("w3wp.exe", "w3wp.exe -ap \"DefaultAppPool\"", None, user)
    file_system[f"{webroot}\\{shell_name}"] = {"sha256": sha256, "size": 2048, "created_by_pid": w3wp.pid}
    base.append_log(emitter.device_file_event(
        "FileCreated", shell_name, webroot, sha256, 2048, w3wp))

    # 2. The web shell executing a command (w3wp.exe spawns cmd/powershell).
    child = process_tree.spawn(
        "cmd.exe", "cmd.exe /c " + data.get("command", "whoami"), "w3wp.exe", user)
    base.append_log(emitter.device_process_event(child, w3wp))

    return jsonify({"status": "deployed", "webShell": shell_name, "processId": child.pid})


# ---------------------------------------------------------------------------
# Endpoints — File operations
# ---------------------------------------------------------------------------


@app.route("/file/create", methods=["POST"])
def file_create():
    """Drop a file to the mock file system."""
    data = request.get_json(force=True)
    file_name = data.get("fileName", "unknown")
    folder_path = data.get("folderPath", "C:\\temp")
    sha256 = data.get("sha256", secrets.token_hex(32))
    file_size = data.get("fileSize", 0)
    created_by_pid = data.get("createdByPid", 0)

    full_path = f"{folder_path}\\{file_name}"
    file_system[full_path] = {
        "sha256": sha256,
        "size": file_size,
        "created_by_pid": created_by_pid,
    }

    proc = process_tree.get_process(created_by_pid)
    log = emitter.device_file_event("FileCreated", file_name, folder_path, sha256, file_size, proc)
    base.append_log(log)

    # Spearphishing attachment (T1566.001): when the dropped file is an
    # email-attachment type (.docm/.doc/.xlsm/.hta/.iso), also emit the
    # Defender-for-Office mail-pipeline rows (EmailEvents + EmailAttachmentInfo)
    # so the email-side Sentinel artifacts are present even on an endpoint-only
    # range that has NO exchange-online service (the lure that delivered the
    # attachment). Routed by Type; append_log stamps the AttackTechnique tag.
    _lure_exts = (".docm", ".doc", ".xlsm", ".xls", ".hta", ".iso", ".lnk")
    if any(file_name.lower().endswith(e) for e in _lure_exts) and data.get("emit_mail", True):
        msg_id = f"msg-{secrets.token_hex(6)}"
        recipient = f"{data.get('user', 'victim')}@{DOMAIN.split('.')[0].lower()}.com"
        _now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        base.append_log({
            "Type": "EmailEvents", "_source": "EmailEvents",
            "Timestamp": _now,
            "NetworkMessageId": msg_id,
            "SenderFromAddress": "billing@vendor-invoices.com",
            "RecipientEmailAddress": recipient,
            "Subject": "Outstanding Invoice Q1 - Action Required",
            "EmailDirection": "Inbound", "DeliveryAction": "Delivered",
            "ThreatTypes": "Phish", "AttachmentCount": 1,
        })
        base.append_log({
            "Type": "EmailAttachmentInfo", "_source": "EmailAttachmentInfo",
            "Timestamp": _now,
            "NetworkMessageId": msg_id,
            "RecipientEmailAddress": recipient,
            "SenderFromAddress": "billing@vendor-invoices.com",
            "FileName": file_name,
            "FileType": file_name.rsplit(".", 1)[-1],
            "SHA256": sha256, "ThreatTypes": "Phish",
        })

    return jsonify({"status": "created", "path": full_path})


@app.route("/file/access", methods=["POST"])
def file_access():
    """Bulk-access local files for collection/staging (T1005 Data from Local System).

    Emits a DeviceFileEvents ``FileAccessed`` row per file — the marker a hunt
    for local-data staging keys on. ``append_log`` stamps the AttackTechnique tag.
    """
    data = request.get_json(force=True)
    files = data.get("files") or [data.get("fileName", "Q3-Financials.xlsx")]
    folder_path = data.get("folderPath", "C:\\Users\\Public\\Documents")
    user = data.get("user", "SYSTEM")
    accessed = []
    for fname in files:
        base.append_log(emitter.device_file_event(
            "FileAccessed", fname, folder_path, "", 262144, None))
        accessed.append(fname)
    return jsonify({"status": "accessed", "files": accessed, "user": user})


@app.route("/file/modify", methods=["POST"])
def file_modify():
    """Modify or rename a file."""
    data = request.get_json(force=True)
    original_path = data.get("originalPath", "")
    new_path = data.get("newPath", original_path)
    modified_by_pid = data.get("modifiedByPid", 0)

    # Determine action
    action = "FileRenamed" if new_path != original_path else "FileModified"

    # Move entry in file system
    entry = file_system.pop(original_path, {"sha256": "", "size": 0, "created_by_pid": 0})
    file_system[new_path] = entry

    file_name = new_path.rsplit("\\", 1)[-1] if "\\" in new_path else new_path
    folder_path = new_path.rsplit("\\", 1)[0] if "\\" in new_path else ""

    proc = process_tree.get_process(modified_by_pid)
    log = emitter.device_file_event(action, file_name, folder_path, entry.get("sha256"), entry.get("size"), proc)
    base.append_log(log)

    return jsonify({"status": action.lower(), "path": new_path})


@app.route("/file/<path:file_path>", methods=["DELETE"])
def file_delete(file_path: str):
    """Delete a file."""
    # Normalize path
    normalized = file_path.replace("/", "\\")
    if not normalized.startswith("C:"):
        normalized = f"C:\\{normalized}"

    entry = file_system.pop(normalized, None)
    file_name = normalized.rsplit("\\", 1)[-1] if "\\" in normalized else normalized
    folder_path = normalized.rsplit("\\", 1)[0] if "\\" in normalized else ""

    log = emitter.device_file_event("FileDeleted", file_name, folder_path)
    base.append_log(log)

    return jsonify({"status": "deleted", "path": normalized})


# ---------------------------------------------------------------------------
# Endpoints — Registry operations
# ---------------------------------------------------------------------------


@app.route("/registry/write", methods=["POST"])
def registry_write():
    """Write a registry key/value."""
    data = request.get_json(force=True)
    key = data.get("registryKey", "")
    value_name = data.get("valueName", "")
    value_data = data.get("valueData", "")
    value_type = data.get("valueType", "REG_SZ")
    written_by_pid = data.get("writtenByPid", 0)

    registry[f"{key}\\{value_name}"] = {
        "data": value_data,
        "type": value_type,
        "pid": written_by_pid,
    }

    proc = process_tree.get_process(written_by_pid)
    log = emitter.device_registry_event("RegistryValueSet", key, value_name, value_data, proc, value_type)
    base.append_log(log)

    return jsonify({"status": "written", "key": key, "valueName": value_name})


@app.route("/registry/read/<path:key_path>", methods=["GET"])
def registry_read(key_path: str):
    """Read a registry value."""
    normalized = key_path.replace("/", "\\")

    # Search for matching entries
    matches = {k: v for k, v in registry.items() if k.startswith(normalized)}

    log = emitter.device_registry_event("RegistryValueRead", normalized, None, None)
    base.append_log(log)

    if matches:
        return jsonify({"key": normalized, "values": matches})
    return jsonify({"key": normalized, "values": {}, "note": "Key not found"})


# ---------------------------------------------------------------------------
# Endpoints — Persistence operations
# ---------------------------------------------------------------------------


@app.route("/scheduled-task/create", methods=["POST"])
def scheduled_task_create():
    """Create a scheduled task (emits schtasks.exe process event)."""
    data = request.get_json(force=True)
    task_name = data.get("taskName", "Task1")
    command = data.get("command", "cmd.exe")
    trigger = data.get("trigger", "once")
    user = data.get("user", "SYSTEM")

    cmd_line = f'schtasks.exe /create /tn "{task_name}" /tr "{command}" /sc {trigger}'
    proc = process_tree.spawn("schtasks.exe", cmd_line, None, user)

    log = emitter.device_process_event(proc)
    base.append_log(log)

    # SecurityEvent 4698 — a scheduled task was created (the T1053.005 Sentinel
    # marker; the schtasks DeviceProcessEvents above is the Defender marker).
    base.append_log({
        "TimeGenerated": datetime.now(timezone.utc).isoformat(),
        "Computer": emitter.device_name,
        "EventID": 4698,
        "Activity": "4698 - A scheduled task was created.",
        "Channel": "Security",
        "SubjectUserName": user,
        "TaskName": f"\\{task_name}",
        "TaskContent": cmd_line,
        "Type": "SecurityEvent",
    })

    return jsonify({
        "status": "created",
        "taskName": task_name,
        "processId": proc.pid,
    })


@app.route("/service/create", methods=["POST"])
def service_create():
    """Install or manage a Windows service."""
    data = request.get_json(force=True)
    service_name = data.get("serviceName", "SvcHost")
    binary_path = data.get("binaryPath", "C:\\Windows\\System32\\svchost.exe")
    user = data.get("user", "SYSTEM")

    cmd_line = f'sc.exe create "{service_name}" binpath= "{binary_path}"'
    proc = process_tree.spawn("sc.exe", cmd_line, None, user)

    log = emitter.device_process_event(proc)
    base.append_log(log)

    return jsonify({
        "status": "created",
        "serviceName": service_name,
        "processId": proc.pid,
    })


# ---------------------------------------------------------------------------
# Endpoints — Network operations
# ---------------------------------------------------------------------------


@app.route("/network/connect", methods=["POST"])
def network_connect():
    """Record an outbound network connection."""
    data = request.get_json(force=True)
    remote_ip = data.get("remoteIp", "0.0.0.0")
    remote_port = data.get("remotePort", 443)
    protocol = data.get("protocol", "tcp")
    remote_url = data.get("remoteUrl", "")
    initiating_pid = data.get("initiatingPid", 0)

    proc = process_tree.get_process(initiating_pid)
    log = emitter.device_network_event(remote_ip, remote_port, protocol=protocol,
                                       process_info=proc, remote_url=remote_url)
    base.append_log(log)

    return jsonify({
        "status": "connected",
        "remoteIp": remote_ip,
        "remotePort": remote_port,
    })


@app.route("/logon", methods=["POST"])
def logon():
    """Record an inbound logon on this host (e.g. remote SMB/RDP authentication).

    Emits BOTH a Defender ``DeviceLogonEvents`` row and a Windows
    ``SecurityEvent`` (4624) — the two surfaces a lateral-movement logon shows up
    on. Lateral-movement staging calls this on the *target* host so SMB/admin-
    share movement (T1021.002) leaves a Network logon (type 3) in both tables.
    """
    data = request.get_json(force=True)
    account = data.get("user", data.get("account", "SYSTEM"))
    logon_type = data.get("logonType", "Network")
    source_ip = data.get("sourceIp", data.get("remoteIp", ""))
    source_host = data.get("sourceHost", "")
    type_id = {"Network": 3, "Interactive": 2, "RemoteInteractive": 10,
               "Batch": 4, "Service": 5}.get(logon_type, 3)

    base.append_log(emitter.device_logon_event(
        account_name=account, logon_type=logon_type,
        remote_ip=source_ip, remote_device=source_host,
    ))
    base.append_log(emitter.security_event_logon(
        account_name=account, logon_type_id=type_id,
        source_ip=source_ip, source_host=source_host,
    ))

    return jsonify({
        "status": "logged_on",
        "account": account,
        "logonType": logon_type,
    })


# ---------------------------------------------------------------------------
# Endpoints — Credential operations
# ---------------------------------------------------------------------------


@app.route("/credential/dump-lsass", methods=["POST"])
def credential_dump_lsass():
    """LSASS memory dump — returns mock credentials."""
    data = request.get_json(force=True)
    tool = data.get("tool", "mimikatz")
    command_line = data.get("commandLine", f"{tool} sekurlsa::logonpasswords")
    user = data.get("user", "SYSTEM")
    sha256 = data.get("sha256")

    # Spawn the tool process
    proc = process_tree.spawn(
        f"{tool}.exe" if "." not in tool else tool,
        command_line,
        None,
        user,
        sha256=sha256,
    )

    # Tag this process event as an LSASS dump so the MDATP alert engine's
    # MDATP-012 rule (match: _event_type == "lsass_dump") fires → SecurityAlert
    # "Suspicious LSASS memory access". The marker rides in the same row, so the
    # DeviceProcessEvents defender signal (ProcessCommandLine ~ "lsass") and the
    # Sentinel SecurityAlert both derive from one tagged emission.
    log = emitter.device_process_event(proc)
    log["_event_type"] = "lsass_dump"
    base.append_log(log)

    # Return pre-seeded credentials or defaults
    creds = lsass_credentials if lsass_credentials else [
        {
            "username": "admin",
            "domain": DOMAIN,
            "ntlm_hash": f"aad3b435b51404eeaad3b435b51404ee:{secrets.token_hex(16)}",
            "password": None,
        },
    ]

    return jsonify({"credentials": creds, "processId": proc.pid})


@app.route("/credential/steal-prt", methods=["POST"])
def credential_steal_prt():
    """PRT token theft — returns mock Primary Refresh Token."""
    data = request.get_json(force=True)
    user = data.get("user", "SYSTEM")

    proc = process_tree.spawn(
        "powershell.exe",
        "powershell.exe -Command Get-UserPRTToken",
        None,
        user,
    )

    log = emitter.device_process_event(proc)
    base.append_log(log)

    # Generate mock PRT
    import base64
    import json as json_mod

    header = base64.b64encode(json_mod.dumps({"alg": "RS256", "typ": "JWT"}).encode()).decode()
    payload = base64.b64encode(json_mod.dumps({
        "device_id": DEVICE_ID,
        "session_key": secrets.token_hex(32),
    }).encode()).decode()
    sig = secrets.token_urlsafe(32)
    prt = f"{header}.{payload}.{sig}"

    return jsonify({"prt": prt, "processId": proc.pid})


# ---------------------------------------------------------------------------
# Endpoints — Defense evasion & impact
# ---------------------------------------------------------------------------


@app.route("/defender/disable", methods=["POST"])
def defender_disable():
    """Disable Windows Defender real-time monitoring."""
    data = request.get_json(force=True)
    user = data.get("user", "SYSTEM")

    proc = process_tree.spawn(
        "powershell.exe",
        "powershell.exe -Command Set-MpPreference -DisableRealtimeMonitoring $true",
        None,
        user,
    )

    log = emitter.device_process_event(proc)
    base.append_log(log)

    # 4719 — system audit policy changed (the Sentinel SecurityEvent artifact of
    # defender/audit tampering, T1562.001).
    base.append_log(emitter.security_event_audit_policy_change(account_name=user))

    return jsonify({"status": "disabled", "processId": proc.pid})


@app.route("/vss/delete", methods=["POST"])
def vss_delete():
    """Delete volume shadow copies."""
    data = request.get_json(force=True)
    user = data.get("user", "SYSTEM")

    proc = process_tree.spawn(
        "vssadmin.exe",
        "vssadmin.exe delete shadows /all /quiet",
        None,
        user,
    )

    log = emitter.device_process_event(proc)
    base.append_log(log)

    return jsonify({"status": "deleted", "processId": proc.pid})


@app.route("/ransomware/deploy", methods=["POST"])
def ransomware_deploy():
    """Ransomware encryption (T1486) — the full impact behaviour.

    Leaves the two distinctive Defender artifacts of an encryption event:
      * DeviceProcessEvents — ``vssadmin delete shadows`` (inhibit recovery before
        encrypting), the ProcessCommandLine the registry keys on.
      * DeviceFileEvents — mass rename of victim files to the ransom extension
        (default ``.encrypted``), which also trips the MDATP ransomware rule.
    """
    data = request.get_json(force=True)
    user = data.get("user", "SYSTEM")
    extension = data.get("extension", ".encrypted")
    if not extension.startswith("."):
        extension = "." + extension
    file_count = int(data.get("fileCount", 3))

    # 1. Inhibit recovery — vssadmin shadow-copy deletion.
    vss_proc = process_tree.spawn(
        "vssadmin.exe",
        "vssadmin.exe delete shadows /all /quiet",
        None,
        user,
    )
    base.append_log(emitter.device_process_event(vss_proc))

    # 2. The encryptor process.
    enc_proc = process_tree.spawn(
        "lockbit.exe",
        f"lockbit.exe --encrypt --ext {extension} --path C:\\Users",
        None,
        user,
    )
    base.append_log(emitter.device_process_event(enc_proc))

    # 3. Mass file rename to the ransom extension (FileRenamed → .encrypted).
    renamed = []
    for i in range(max(1, file_count)):
        orig = f"C:\\Users\\{user}\\Documents\\report_{i}.xlsx"
        new = orig + extension
        file_system[new] = file_system.pop(orig, {"sha256": "", "size": 524288, "created_by_pid": 0})
        fname = new.rsplit("\\", 1)[-1]
        folder = new.rsplit("\\", 1)[0]
        base.append_log(emitter.device_file_event(
            "FileRenamed", fname, folder, "", 524288, enc_proc))
        renamed.append(new)

    return jsonify({"status": "encrypted", "extension": extension,
                    "filesEncrypted": len(renamed), "processId": enc_proc.pid})


@app.route("/bcdedit/modify", methods=["POST"])
def bcdedit_modify():
    """Modify boot configuration to disable recovery."""
    data = request.get_json(force=True)
    user = data.get("user", "SYSTEM")

    proc = process_tree.spawn(
        "bcdedit.exe",
        "bcdedit.exe /set recoveryenabled No",
        None,
        user,
    )

    log = emitter.device_process_event(proc)
    base.append_log(log)

    return jsonify({"status": "modified", "processId": proc.pid})


# ---------------------------------------------------------------------------
# Endpoints — Admin/config
# ---------------------------------------------------------------------------


@app.route("/admin/config", methods=["POST"])
def admin_config():
    """Inject runtime configuration (pre-seeded LSASS credentials, etc.)."""
    global lsass_credentials
    data = request.get_json(force=True)

    if "lsass_credentials" in data:
        lsass_credentials = data["lsass_credentials"]

    return jsonify({"status": "configured"})


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
