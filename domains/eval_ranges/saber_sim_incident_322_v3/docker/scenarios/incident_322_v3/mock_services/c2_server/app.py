"""
Mock C2 (Command & Control) Server

Simulates a C2 framework (Cobalt Strike, Sliver, etc.) with beacon
registration, check-in, task assignment, and payload hosting.
"""

import os
import json
import secrets
import base64
import uuid
from datetime import datetime, timezone
from flask import Flask, request, jsonify, Response
from mock_service_base import MockServiceBase, create_base_blueprint

app = Flask(__name__)
base = MockServiceBase('c2-server')
app.register_blueprint(create_base_blueprint(base))

# State
BEACONS = {}       # beacon_id -> {hostname, user, pid, type, tasks, checkins}
PAYLOADS = {}      # name -> {content_type, content_bytes}
TASK_QUEUE = {}    # beacon_id -> [tasks]


@app.route('/beacon/register', methods=['POST'])
def register_beacon():
    """Register a new beacon (compromised host checks in to C2)."""
    data = request.get_json(force=True)
    beacon_id = f"beacon-{len(BEACONS) + 1:03d}"

    beacon = {
        "beaconId": beacon_id,
        "hostname": data.get("hostname", "unknown"),
        "user": data.get("user", "unknown"),
        "pid": data.get("pid", 0),
        "beacon_type": data.get("beacon_type", "http"),
        "registered": datetime.now(timezone.utc).isoformat(),
        "last_checkin": None,
        "checkin_count": 0,
    }
    BEACONS[beacon_id] = beacon
    TASK_QUEUE[beacon_id] = []

    base.append_log({
        "Timestamp": beacon["registered"],
        "Operation": "BeaconRegistered",
        "BeaconId": beacon_id,
        "Hostname": beacon["hostname"],
        "User": beacon["user"],
        "PID": beacon["pid"],
        "BeaconType": beacon["beacon_type"],
        "_source": "c2_server",
    })

    # DeviceNetworkEvents — the compromised host's outbound C2 connection (the
    # T1071 / T1071.004 Defender marker). Port by channel: DNS tunneling = 53,
    # HTTPS = 443, HTTP = 80. DeviceName is the victim host (beacon hostname).
    # ``append_log`` stamps the AttackTechnique tag from the request header.
    _btype = (beacon["beacon_type"] or "http").lower()
    _port = {"dns": 53, "https": 443, "http": 80}.get(_btype, 443)
    _c2_domain = data.get("c2_domain") or data.get("domain") or "update-check.systemcdn.net"
    base.append_log({
        "Timestamp": beacon["registered"],
        "DeviceName": beacon["hostname"],
        "ActionType": "ConnectionSuccess",
        "RemoteIP": "203.0.113.66",
        "RemotePort": _port,
        "RemoteUrl": _c2_domain,
        "Protocol": "udp" if _btype == "dns" else "tcp",
        "InitiatingProcessFileName": "svchost.exe" if _btype == "dns" else "rundll32.exe",
        "InitiatingProcessCommandLine": (
            f"nslookup -type=TXT {_c2_domain}" if _btype == "dns"
            else f"beacon -> https://{_c2_domain}"),
        "Type": "DeviceNetworkEvents",
    })

    return jsonify({
        "beaconId": beacon_id,
        "sleep_interval": 60,
        "jitter": 10,
        "status": "registered",
    })


@app.route('/beacon/<beacon_id>/checkin', methods=['POST'])
def beacon_checkin(beacon_id):
    """Periodic beacon callback. Returns any queued tasks."""
    if beacon_id not in BEACONS:
        return jsonify({"error": "Unknown beacon"}), 404

    BEACONS[beacon_id]["last_checkin"] = datetime.now(timezone.utc).isoformat()
    BEACONS[beacon_id]["checkin_count"] += 1

    tasks = TASK_QUEUE.get(beacon_id, [])
    TASK_QUEUE[beacon_id] = []

    return jsonify({"tasks": tasks, "sleep_interval": 60})


@app.route('/beacon/<beacon_id>/task', methods=['GET', 'POST'])
def beacon_task(beacon_id):
    """GET: Get next pending task. POST: Queue a task for the beacon."""
    if beacon_id not in BEACONS:
        return jsonify({"error": "Unknown beacon"}), 404

    if request.method == 'POST':
        data = request.get_json(force=True)
        task = {
            "id": f"task-{len(TASK_QUEUE.get(beacon_id, [])) + 1:03d}",
            "type": data.get("type", "execute"),
            "command": data.get("command", ""),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        TASK_QUEUE.setdefault(beacon_id, []).append(task)
        return jsonify(task), 201

    # GET — return next task
    tasks = TASK_QUEUE.get(beacon_id, [])
    if tasks:
        return jsonify(tasks[0])
    return jsonify({"tasks": [], "message": "No pending tasks"})


@app.route('/payload/host', methods=['POST'])
def host_payload():
    """Host a payload for download by compromised hosts."""
    data = request.get_json(force=True)
    name = data.get("name", "payload.bin")
    content_type = data.get("content_type", "application/octet-stream")
    content_b64 = data.get("content_b64", "")

    try:
        content = base64.b64decode(content_b64)
    except Exception:
        content = content_b64.encode()

    # Cap payload size at 1MB
    if len(content) > 1_048_576:
        return jsonify({"error": "Payload too large", "max_bytes": 1_048_576}), 413

    PAYLOADS[name] = {"content_type": content_type, "content": content}

    base.append_log({
        "Timestamp": datetime.now(timezone.utc).isoformat(),
        "Operation": "PayloadHosted",
        "PayloadName": name,
        "Size": len(content),
        "_source": "c2_server",
    })

    return jsonify({"name": name, "size": len(content), "status": "hosted"})


@app.route('/payload/<name>', methods=['GET'])
def serve_payload(name):
    """Serve a hosted payload."""
    payload = PAYLOADS.get(name)
    if not payload:
        return jsonify({"error": "Payload not found"}), 404

    return Response(
        payload["content"],
        mimetype=payload["content_type"],
        headers={"Content-Disposition": f"attachment; filename={name}"},
    )


@app.route('/beacons', methods=['GET'])
def list_beacons():
    """List all registered beacons."""
    return jsonify({"beacons": list(BEACONS.values()), "count": len(BEACONS)})


if __name__ == '__main__':
    print("[C2] Starting C2 server")
    app.run(host='0.0.0.0', port=8080, threaded=True)
