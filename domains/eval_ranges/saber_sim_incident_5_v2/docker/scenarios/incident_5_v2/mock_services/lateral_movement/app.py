"""
Mock Lateral Movement Coordinator Service

Orchestrates lateral movement operations across multiple endpoint hosts.
Routes commands to windows-endpoint services and generates correlated
events on both source and target hosts.

Supports: PsExec, WMI, SMB file copy, RDP, Impacket.
"""

import os
import json
import uuid
import time
from datetime import datetime, timezone
from flask import Flask, request, jsonify
import requests as http_client
from mock_service_base import MockServiceBase, create_base_blueprint

app = Flask(__name__)
base = MockServiceBase('lateral-movement-coordinator')
app.register_blueprint(create_base_blueprint(base))

# Parse HOSTS env var: "host1:8080,host2:8080"
HOSTS = {}
for entry in os.environ.get('HOSTS', '').split(','):
    entry = entry.strip()
    if ':' in entry:
        name, port = entry.rsplit(':', 1)
        HOSTS[name] = f"http://{name}:{port}"
    elif entry:
        HOSTS[entry] = f"http://{entry}:8080"

# Movement history
MOVEMENT_LOG = []
TOPOLOGY = {}  # host -> [connected_hosts]

TIMEOUT = int(os.environ.get('HTTP_TIMEOUT', '5'))


def _attack_header():
    """Forward the capture tag from the inbound request to internal calls.

    Lateral movement fans an attack out to windows-endpoint routes via
    server-to-server POSTs. Those derived rows must carry the same
    ``X-Saber-Attack-Technique`` tag as the originating run_scenario curl, else
    tag-authoritative capture drops them.
    """
    try:
        tid = request.headers.get('X-Saber-Attack-Technique')
    except Exception:
        tid = None
    return {'X-Saber-Attack-Technique': tid} if tid else {}


def _call_endpoint(host_url, path, payload, retries=3):
    """POST to a windows-endpoint service with retry. Returns response dict or error."""
    last_error = None
    headers = _attack_header()
    for attempt in range(retries):
        try:
            resp = http_client.post(
                f"{host_url}{path}",
                json=payload,
                headers=headers,
                timeout=TIMEOUT,
            )
            return resp.json() if resp.ok else {"error": resp.text, "status": resp.status_code}
        except Exception as e:
            last_error = e
            if attempt < retries - 1:
                import time
                time.sleep(1)
    return {"error": str(last_error)}


def _record_movement(movement_type, source, target, source_user, details=None):
    """Record a lateral movement event for topology tracking."""
    entry = {
        "id": str(uuid.uuid4()),
        "type": movement_type,
        "source": source,
        "target": target,
        "source_user": source_user,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": details or {},
    }
    MOVEMENT_LOG.append(entry)
    TOPOLOGY.setdefault(source, set()).add(target)
    base.append_log({
        "_event_type": f"lateral_{movement_type}",
        "source_host": source,
        "target_host": target,
        "user": source_user,
        "timestamp": entry["timestamp"],
        "_source": "lateral_movement",
    })
    return entry


@app.route('/psexec/<target>', methods=['POST'])
def psexec(target):
    """PsExec lateral movement — creates events on both source and target.

    1. Source: network connect (SMB 445)
    2. Source: process execute (PsExec.exe)
    3. Target: service create (PSEXESVC)
    4. Target: process execute (the actual command)
    """
    data = request.get_json() or {}
    source_host = data.get('source_host', 'unknown')
    source_user = data.get('source_user', 'unknown')
    # Pass-the-hash / over-pass-the-hash authenticates to the TARGET as the
    # harvested/escalated credential, not the source operator. When the
    # run_scenario threads ``target_user`` (the lateral target's account, e.g. the
    # LSASS-harvested admin) the target-side events are emitted under THAT
    # identity; absent it we fall back to the source user.
    target_user = data.get('target_user') or source_user
    command = data.get('command', 'cmd.exe /c whoami')
    tool_sha256 = data.get('tool_sha256', '')

    source_url = HOSTS.get(source_host)
    target_url = HOSTS.get(target)
    results = {"source_events": 0, "target_events": 0}

    # 1. Source: SMB connection to target
    if source_url:
        _call_endpoint(source_url, '/network/connect', {
            "remoteIp": target,
            "remotePort": 445,
            "protocol": "tcp",
            "processName": "PsExec.exe",
        })
        results["source_events"] += 1

    # 2. Source: PsExec process execution
    if source_url:
        _call_endpoint(source_url, '/process/execute', {
            "fileName": "PsExec.exe",
            "commandLine": f"PsExec.exe \\\\{target} -accepteula {command}",
            "parentProcess": "cmd.exe",
            "user": source_user,
            "sha256": tool_sha256,
        })
        results["source_events"] += 1

    # 3. Target: PSEXESVC service creation
    if target_url:
        _call_endpoint(target_url, '/service/create', {
            "serviceName": "PSEXESVC",
            "binaryPath": "C:\\Windows\\PSEXESVC.exe",
            "user": target_user,
        })
        results["target_events"] += 1

    # 4. Target: actual command execution
    if target_url:
        cmd_result = _call_endpoint(target_url, '/process/execute', {
            "fileName": command.split()[0] if command else "cmd.exe",
            "commandLine": command,
            "parentProcess": "PSEXESVC.exe",
            "user": target_user,
        })
        results["target_events"] += 1
        results["target_pid"] = cmd_result.get("processId", 0)

    results["status"] = "success"
    _record_movement("psexec", source_host, target, source_user, {"command": command})

    return jsonify(results)


@app.route('/wmi/<target>', methods=['POST'])
def wmi(target):
    """WMI remote execution.

    1. Source: network connect (WMI port 135 + dynamic)
    2. Target: process execute (wmiprvse.exe → child command)
    """
    data = request.get_json() or {}
    source_host = data.get('source_host', 'unknown')
    source_user = data.get('source_user', 'unknown')
    target_user = data.get('target_user') or source_user
    command = data.get('command', 'cmd.exe /c whoami')

    source_url = HOSTS.get(source_host)
    target_url = HOSTS.get(target)
    results = {"source_events": 0, "target_events": 0}

    if source_url:
        _call_endpoint(source_url, '/network/connect', {
            "remoteIp": target,
            "remotePort": 135,
            "protocol": "tcp",
            "processName": "wmic.exe",
        })
        results["source_events"] += 1
        # Also run the wmic client process on the source so the 'wmic'
        # ProcessCommandLine marker (T1047 DeviceProcessEvents signal) is
        # present — mirrors the /winrm/ client-process marker.
        _call_endpoint(source_url, '/process/execute', {
            "fileName": "wmic.exe",
            "commandLine": f"wmic /node:{target} process call create \"{command}\"",
            "parentProcess": "cmd.exe",
            "user": source_user,
        })
        results["source_events"] += 1

    if target_url:
        cmd_result = _call_endpoint(target_url, '/process/execute', {
            "fileName": command.split()[0] if command else "cmd.exe",
            "commandLine": command,
            "parentProcess": "wmiprvse.exe",
            "user": target_user,
        })
        results["target_events"] += 1
        results["target_pid"] = cmd_result.get("processId", 0)

    results["status"] = "success"
    _record_movement("wmi", source_host, target, source_user, {"command": command})

    return jsonify(results)

@app.route('/winrm/<target>', methods=['POST'])
def winrm(target):
    """WinRM / PSRemoting remote execution (T1021.006).

    1. Source: network connect to WinRM (5985) — the DeviceNetworkEvents marker.
    2. Target: process execute (winrm/wsmprovhost.exe → child command) — the
       DeviceProcessEvents ``winrm`` ProcessCommandLine marker.
    """
    data = request.get_json() or {}
    source_host = data.get('source_host', 'unknown')
    source_user = data.get('source_user', 'unknown')
    target_user = data.get('target_user') or source_user
    command = data.get('command', 'powershell.exe -Command whoami')

    source_url = HOSTS.get(source_host)
    target_url = HOSTS.get(target)
    results = {"source_events": 0, "target_events": 0}

    if source_url:
        _call_endpoint(source_url, '/network/connect', {
            "remoteIp": target,
            "remotePort": 5985,
            "protocol": "tcp",
            "processName": "winrm.exe",
        })
        results["source_events"] += 1
        # Also run the winrm client process on the source so the 'winrm'
        # ProcessCommandLine marker is present.
        _call_endpoint(source_url, '/process/execute', {
            "fileName": "winrm.exe",
            "commandLine": f"winrm.exe invoke Create wmicimv2/Win32_Process -r:http://{target}:5985 @{{CommandLine=\"{command}\"}}",
            "parentProcess": "cmd.exe",
            "user": source_user,
        })
        results["source_events"] += 1

    if target_url:
        cmd_result = _call_endpoint(target_url, '/process/execute', {
            "fileName": command.split()[0] if command else "powershell.exe",
            "commandLine": command,
            "parentProcess": "wsmprovhost.exe",
            "user": target_user,
        })
        results["target_events"] += 1
        results["target_pid"] = cmd_result.get("processId", 0)

    results["status"] = "success"
    _record_movement("winrm", source_host, target, source_user, {"command": command})

    return jsonify(results)

@app.route('/smb/<target>/copy', methods=['POST'])
def smb_copy(target):
    """SMB file transfer (tool staging).

    1. Source: network connect (SMB 445)
    2. Target: file create
    """
    data = request.get_json() or {}
    source_host = data.get('source_host', 'unknown')
    source_user = data.get('source_user', 'unknown')
    target_user = data.get('target_user') or source_user
    file_name = data.get('file_name', 'payload.exe')
    file_sha256 = data.get('file_sha256', '')
    destination_path = data.get('destination_path', f'C:\\Windows\\Temp\\{file_name}')

    source_url = HOSTS.get(source_host)
    target_url = HOSTS.get(target)
    results = {"source_events": 0, "target_events": 0}

    if source_url:
        _call_endpoint(source_url, '/network/connect', {
            "remoteIp": target,
            "remotePort": 445,
            "protocol": "tcp",
            "processName": "explorer.exe",
        })
        results["source_events"] += 1

    if target_url:
        folder = destination_path.rsplit('\\', 1)[0] if '\\' in destination_path else 'C:\\Windows\\Temp'
        _call_endpoint(target_url, '/file/create', {
            "fileName": file_name,
            "folderPath": folder,
            "sha256": file_sha256,
            "fileSize": data.get('file_size', 245760),
        })
        results["target_events"] += 1

        # Network logon on the target (admin-share auth) — leaves a Network
        # logon (type 3) in BOTH DeviceLogonEvents and SecurityEvent (4624),
        # the Defender + Sentinel surfaces for SMB/admin-share movement. Emitted
        # AS target_user (the harvested credential presented to the target).
        _call_endpoint(target_url, '/logon', {
            "user": target_user,
            "logonType": "Network",
            "sourceHost": source_host,
            "sourceIp": source_host,
        })
        results["target_events"] += 1

    results["status"] = "success"
    _record_movement("smb_copy", source_host, target, source_user, {
        "file": file_name, "destination": destination_path,
    })

    return jsonify(results)


@app.route('/rdp/<target>', methods=['POST'])
def rdp(target):
    """RDP lateral movement.

    Source: network connect (3389)
    Target: logon event (Type 10 = RemoteInteractive)
    """
    data = request.get_json() or {}
    source_host = data.get('source_host', 'unknown')
    source_user = data.get('source_user', 'unknown')

    source_url = HOSTS.get(source_host)
    target_url = HOSTS.get(target)
    results = {"source_events": 0, "target_events": 0}

    if source_url:
        _call_endpoint(source_url, '/network/connect', {
            "remoteIp": target,
            "remotePort": 3389,
            "protocol": "tcp",
            "processName": "mstsc.exe",
        })
        results["source_events"] += 1

    # Target RDP logon (Type 10 = RemoteInteractive) — leaves the
    # DeviceLogonEvents (Defender) + SecurityEvent 4624 (Sentinel) artifacts of
    # an RDP session on the target host (the T1021.001 markers). Mirrors the
    # smb_copy network-logon fan-out. _call_endpoint forwards the
    # X-Saber-Attack-Technique tag so both rows are captured.
    if target_url:
        _call_endpoint(target_url, '/logon', {
            "user": data.get('target_user') or source_user,
            "logonType": "RemoteInteractive",
            "sourceHost": source_host,
            "sourceIp": source_host,
        })
        results["target_events"] += 1
    results["status"] = "success"
    _record_movement("rdp", source_host, target, source_user)

    return jsonify(results)


@app.route('/impacket/<target>', methods=['POST'])
def impacket(target):
    """Impacket toolkit (SMB/WMI combo — used in incident 55 for ADFS access).

    Combines SMB connection + WMI execution.
    """
    data = request.get_json() or {}
    source_host = data.get('source_host', 'unknown')
    source_user = data.get('source_user', 'unknown')
    command = data.get('command', 'cmd.exe /c whoami')
    tool = data.get('tool', 'smbexec.py')

    source_url = HOSTS.get(source_host)
    target_url = HOSTS.get(target)
    results = {"source_events": 0, "target_events": 0}

    # SMB connection
    if source_url:
        _call_endpoint(source_url, '/network/connect', {
            "remoteIp": target,
            "remotePort": 445,
            "protocol": "tcp",
            "processName": "python3",
        })
        results["source_events"] += 1

    # Remote execution
    if target_url:
        cmd_result = _call_endpoint(target_url, '/process/execute', {
            "fileName": command.split()[0] if command else "cmd.exe",
            "commandLine": command,
            "parentProcess": "services.exe",
            "user": data.get('target_user') or source_user,
        })
        results["target_events"] += 1
        results["target_pid"] = cmd_result.get("processId", 0)

    results["status"] = "success"
    _record_movement("impacket", source_host, target, source_user, {
        "tool": tool, "command": command,
    })

    return jsonify(results)


@app.route('/topology', methods=['GET'])
def get_topology():
    """Return host graph with all recorded lateral movement history."""
    # Convert sets to lists for JSON serialization
    topo = {host: sorted(targets) for host, targets in TOPOLOGY.items()}
    return jsonify({
        "hosts": sorted(HOSTS.keys()),
        "topology": topo,
        "movements": MOVEMENT_LOG,
        "total_movements": len(MOVEMENT_LOG),
    })


if __name__ == '__main__':
    print(f"[LateralMovement] Starting with hosts: {list(HOSTS.keys())}")
    app.run(host='0.0.0.0', port=8080, threaded=True)
