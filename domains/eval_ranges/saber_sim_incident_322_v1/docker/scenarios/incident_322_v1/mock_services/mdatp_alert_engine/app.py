"""
Mock MDATP Alert Engine Service

Pattern-matching engine that evaluates security events against detection
rules and generates MDE-style alerts.  Can be queried for alerts or
receive events via POST for real-time evaluation.
"""

import os
import json
import threading
import time
from datetime import datetime, timezone
from flask import Flask, request, jsonify
import requests as http_client
from mock_service_base import MockServiceBase, create_base_blueprint
from rules import RULES
from evaluator import AlertEvaluator

app = Flask(__name__)
base = MockServiceBase('mdatp-alert-engine')
app.register_blueprint(create_base_blueprint(base))

evaluator = AlertEvaluator(RULES)

# Endpoints to poll for events
ENDPOINTS = {}
for entry in os.environ.get('ENDPOINTS', '').split(','):
    entry = entry.strip()
    if ':' in entry:
        name, port = entry.rsplit(':', 1)
        ENDPOINTS[name] = f"http://{name}:{port}"
    elif entry:
        ENDPOINTS[entry] = f"http://{entry}:8080"

POLL_INTERVAL = int(os.environ.get('POLL_INTERVAL', '10'))
TIMEOUT = int(os.environ.get('HTTP_TIMEOUT', '5'))

# Track last-seen log count per endpoint to avoid re-processing
_last_seen = {}


@app.route('/evaluate', methods=['POST'])
def evaluate_events():
    """Evaluate a batch of events against detection rules."""
    events = request.get_json()
    if isinstance(events, dict):
        events = [events]
    new_alerts = evaluator.evaluate(events)
    # Also append to base audit log
    for alert in new_alerts:
        base.append_log(alert)
    return jsonify({
        "alerts": new_alerts,
        "count": len(new_alerts),
        "total_alerts": len(evaluator.alerts),
    })


@app.route('/alerts', methods=['GET'])
def get_alerts():
    """Return all generated alerts."""
    severity = request.args.get('severity')
    alerts = evaluator.get_alerts(severity)
    return jsonify({
        "alerts": alerts,
        "count": len(alerts),
    })


@app.route('/alerts/summary', methods=['GET'])
def alert_summary():
    """Return alert summary grouped by severity and category."""
    alerts = evaluator.alerts
    by_severity = {}
    by_category = {}
    by_rule = {}
    for a in alerts:
        by_severity[a["severity"]] = by_severity.get(a["severity"], 0) + 1
        by_category[a["category"]] = by_category.get(a["category"], 0) + 1
        by_rule[a["ruleId"]] = by_rule.get(a["ruleId"], 0) + 1
    return jsonify({
        "total": len(alerts),
        "by_severity": by_severity,
        "by_category": by_category,
        "by_rule": by_rule,
    })


@app.route('/rules', methods=['GET'])
def list_rules():
    """Return all detection rules (without match functions)."""
    return jsonify({
        "rules": [
            {k: v for k, v in rule.items() if k != "match"}
            for rule in RULES
        ],
        "count": len(RULES),
    })


def _poll_endpoints():
    """Background thread: poll endpoint /audit/logs for new events."""
    while True:
        time.sleep(POLL_INTERVAL)
        for name, url in ENDPOINTS.items():
            try:
                resp = http_client.get(f"{url}/audit/logs", timeout=TIMEOUT)
                if not resp.ok:
                    continue
                data = resp.json()
                logs = data.get("value", data) if isinstance(data, dict) else data
                if not isinstance(logs, list):
                    continue
                last = _last_seen.get(name, 0)
                new_logs = logs[last:]
                if new_logs:
                    new_alerts = evaluator.evaluate(new_logs)
                    for alert in new_alerts:
                        base.append_log(alert)
                    _last_seen[name] = len(logs)
            except Exception:
                continue


if __name__ == '__main__':
    print(f"[MDATP] Starting alert engine with {len(RULES)} rules")
    print(f"[MDATP] Polling endpoints: {list(ENDPOINTS.keys())}")

    if ENDPOINTS:
        poll_thread = threading.Thread(target=_poll_endpoints, daemon=True)
        poll_thread.start()

    app.run(host='0.0.0.0', port=8080, threaded=True)
