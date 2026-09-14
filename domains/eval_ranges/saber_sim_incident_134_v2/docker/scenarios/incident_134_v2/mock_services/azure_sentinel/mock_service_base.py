"""
mock_service_base.py — Shared base for all SABER-SIM mock Azure services.

Provides standardized:
  - /health, /healthz endpoints
  - /audit/logs endpoint ({"value": [...], "count": N})
  - /admin/tokens GET/POST/DELETE
  - /admin/reset POST
  - Thread-safe log buffer with MAX_LOGS cap

Usage:
    from mock_service_base import MockServiceBase, create_base_blueprint

    app = Flask(__name__)
    base = MockServiceBase('keyvault')
    app.register_blueprint(create_base_blueprint(
        base,
        health_extras={'vault': VAULT_NAME}
    ))

    # In your routes:
    base.append_log(log_entry)          # Thread-safe, capped at MAX_LOGS
    base.tokens                         # set() of valid Bearer tokens
    with base.lock:                     # Lock for custom multi-step ops
        ...
"""

import os
import threading
import uuid
from flask import Blueprint, request, jsonify, current_app

MAX_LOGS = 10_000

# Header stamped by run_scenario.sh on every attack curl (Phase 10 live capture).
ATTACK_TECHNIQUE_HEADER = "X-Saber-Attack-Technique"
# Optional per-request attacker source IP (run_scenario.sh may stamp it). Falls
# back to ATTACKER_IP env, then the request socket IP (Docker bridge).
ATTACKER_IP_HEADER = "X-Attacker-IP"


def attacker_source_ip(base=None):
    """Resolve the attacker's source IP for emitted attack telemetry.

    Precedence: ``X-Attacker-IP`` request header (set by run_scenario.sh) →
    ``base.attacker_ip`` (seeded via /admin/identities) → ``ATTACKER_IP`` env →
    the request socket IP. The socket IP is the Docker bridge (e.g. 172.30.x.x),
    which is a capture artifact, NOT the real attacker — so it is the last
    resort. Keeps the attack telemetry's source IP consistent with the range's
    entity_context.attacker_ip (and thus the benign anomaly baseline)."""
    try:
        from flask import has_request_context
        if has_request_context():
            hdr = request.headers.get(ATTACKER_IP_HEADER)
            if hdr:
                return hdr
    except Exception:
        pass
    if base is not None and getattr(base, "attacker_ip", None):
        return base.attacker_ip
    env_ip = os.environ.get("ATTACKER_IP")
    if env_ip:
        return env_ip
    try:
        from flask import has_request_context
        if has_request_context():
            return request.remote_addr
    except Exception:
        pass
    return None


def attack_technique_header():
    """Return the seeded attack technique id for the current request, or None.

    ``run_scenario.sh`` stamps ``X-Saber-Attack-Technique: <tid>`` on every
    attack curl. Mock auth validators use this as a trusted out-of-band signal
    that the request is part of the seeded attack chain — i.e. the attacker is
    wielding a VALID STOLEN token. These are post-compromise techniques whose
    premise is that the attacker already holds valid credentials, so honoring
    the tag lets the real operation execute (and emit the correct telemetry)
    instead of failing auth and emitting a misleading ``Failed`` row. Robust
    across all ranges — it does not depend on the (separately fragile) OAuth
    secret-seeding chain succeeding. Returns None outside a request context.
    """
    try:
        from flask import has_request_context
        if has_request_context():
            return request.headers.get(ATTACK_TECHNIQUE_HEADER)
    except Exception:
        pass
    return None


class MockServiceBase:
    """Shared state and helpers for a mock service."""

    def __init__(self, service_name):
        self.service_name = service_name
        self.lock = threading.RLock()
        self._log_buffers = {}
        self.tokens = set()
        self.config = {}
        # Directory of seeded users: {upn_lower: object_id} so emitted identity
        # telemetry (e.g. SigninLogs UserId) carries the SAME object_id the
        # benign baseline + seed_manifest use, instead of a random uuid4.
        self.identities = {}
        # Attacker source IP for emitted attack telemetry (seeded by the
        # init-seed container or ATTACKER_IP env); see attacker_source_ip().
        self.attacker_ip = os.environ.get("ATTACKER_IP") or None
        # Default acting principal — the COMPROMISED user. The attacker operates
        # with the victim's stolen credentials, so directory/privileged ops are
        # attributed to them whenever the presented token carries no identity
        # claim of its own. Keeps the victim entity present in the attack
        # telemetry (matching the seed + benign baseline) even when the
        # LLM-generated credential chain didn't link the token to a user.
        self.default_actor_upn = os.environ.get("SABER_VICTIM_UPN") or None
        self.default_actor_oid = os.environ.get("SABER_VICTIM_OBJECTID") or None

    def resolve_object_id(self, upn):
        """Object id for a UPN: the seeded directory value, else a STABLE
        uuid5 of the UPN (so the same principal keeps one id across all rows,
        even when not explicitly seeded) — never a fresh random uuid4."""
        if not upn:
            return ""
        oid = self.identities.get(str(upn).lower())
        if oid:
            return oid
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, str(upn).lower()))

    def get_log_buffer(self, name='default'):
        """Get or create a named log buffer."""
        if name not in self._log_buffers:
            self._log_buffers[name] = []
        return self._log_buffers[name]

    def append_log(self, entry, buffer_name='default'):
        """Thread-safe log append with MAX_LOGS cap.

        Phase 10 live capture: if the current request carries the
        ``X-Saber-Attack-Technique`` header (set by ``run_scenario.sh`` on the
        attack curls), stamp it onto the emitted row as ``AttackTechnique`` so
        the capture (and the acceptance test) can distinguish attack telemetry
        from the benign baseline unambiguously — no clock/time-window fragility.
        """
        try:
            if isinstance(entry, dict) and "AttackTechnique" not in entry:
                tid = attack_technique_header()
                if tid:
                    entry["AttackTechnique"] = tid
        except Exception:
            pass
        with self.lock:
            buf = self.get_log_buffer(buffer_name)
            buf.append(entry)
            if len(buf) > MAX_LOGS:
                buf.pop(0)

    def collect_logs(self):
        """
        Collect all logs from all buffers.
        Called with self.lock held by the /audit/logs handler.
        Override in a subclass for custom collection/transformation logic.
        """
        all_logs = []
        for buf in self._log_buffers.values():
            all_logs.extend(buf)
        return list(all_logs)

    def reset(self):
        """Clear all state: logs, tokens, config. Called with self.lock held."""
        for buf in self._log_buffers.values():
            buf.clear()
        self.tokens.clear()
        self.config.clear()
        self.identities.clear()
        self.attacker_ip = os.environ.get("ATTACKER_IP") or None
        self.default_actor_upn = os.environ.get("SABER_VICTIM_UPN") or None
        self.default_actor_oid = os.environ.get("SABER_VICTIM_OBJECTID") or None


def create_base_blueprint(base, health_extras=None,
                          include_audit_logs=True, include_tokens=True):
    """
    Create a Flask Blueprint with standard mock service endpoints.

    Args:
        base: MockServiceBase instance
        health_extras: dict or callable returning dict — merged into /health response
        include_audit_logs: if False, skip /audit/logs (e.g. for sentinel which is the consumer)
        include_tokens: if False, skip /admin/tokens (e.g. for services with custom token logic)

    Returns:
        Flask Blueprint — register with app.register_blueprint(bp)
    """
    blueprint_name = f'mock_base_{base.service_name}'
    bp = Blueprint(blueprint_name, __name__)

    @bp.route('/health', methods=['GET'])
    @bp.route('/healthz', methods=['GET'])
    def health():
        info = {'status': 'healthy', 'service': base.service_name}
        if health_extras:
            extras = health_extras() if callable(health_extras) else health_extras
            info.update(extras)
        return jsonify(info)

    if include_audit_logs:
        @bp.route('/audit/logs', methods=['GET'])
        def audit_logs():
            with base.lock:
                logs = base.collect_logs()
            return jsonify({'value': logs, 'count': len(logs)})

    if include_tokens:
        @bp.route('/admin/tokens', methods=['GET', 'POST', 'DELETE'])
        def admin_tokens():
            if request.method == 'POST':
                data = request.get_json() or {}
                tokens = data.get('tokens', [])
                if isinstance(tokens, str):
                    tokens = [tokens]
                elif not isinstance(tokens, (list, tuple)):
                    tokens = []
                with base.lock:
                    base.tokens.update(tokens)
                count = len(base.tokens)
                print(f'[{base.service_name.upper()}] Injected {len(tokens)} token(s), total: {count}', flush=True)
                return jsonify({'status': 'ok', 'tokens_count': count})
            elif request.method == 'DELETE':
                with base.lock:
                    count = len(base.tokens)
                    base.tokens.clear()
                print(f'[{base.service_name.upper()}] Cleared {count} token(s)', flush=True)
                return jsonify({'status': 'ok', 'cleared': count})
            else:
                with base.lock:
                    tokens_count = len(base.tokens)
                return jsonify({'tokens_count': tokens_count})

    @bp.route('/admin/reset', methods=['POST'])
    def admin_reset():
        with base.lock:
            base.reset()
        print(f'[{base.service_name.upper()}] State reset', flush=True)
        return jsonify({'status': 'reset', 'service': base.service_name})

    @bp.route('/admin/identities', methods=['GET', 'POST'])
    def admin_identities():
        """Seed the UPN→object_id directory (+ optional attacker_ip) so emitted
        attack telemetry references the SAME entity values as the seed_manifest
        and benign baseline. POST body:
            {"identities": {"<upn>": "<object_id>", ...},
             "attacker_ip": "185.x.x.x"}
        """
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            idents = data.get('identities') or {}
            added = 0
            if isinstance(idents, dict):
                with base.lock:
                    for upn, oid in idents.items():
                        if upn and oid:
                            base.identities[str(upn).lower()] = str(oid)
                            added += 1
            atk = data.get('attacker_ip')
            if atk:
                with base.lock:
                    base.attacker_ip = str(atk)
            print(f'[{base.service_name.upper()}] Seeded {added} identitie(s)'
                  f'{", attacker_ip=" + base.attacker_ip if base.attacker_ip else ""}',
                  flush=True)
            return jsonify({'status': 'ok', 'identities_count': len(base.identities),
                            'attacker_ip': base.attacker_ip})
        with base.lock:
            return jsonify({'identities_count': len(base.identities),
                            'attacker_ip': base.attacker_ip})

    @bp.app_errorhandler(404)
    def _mock_not_found(_err):
        """Return a structured, Azure-style JSON 404 that lists the real
        endpoint surface instead of Flask's HTML page.

        Two wins: (1) cuts agent endpoint-probing friction — a wrong path
        (``/``, ``/help``, ``/api/v1/tables``, ``/audit`` …) reveals the
        available routes so the agent stops blindly guessing; (2) removes a
        realism tell — a bare Flask HTML 404 is an obvious mock, whereas a real
        Azure service returns a JSON error envelope. Services that register
        their own ``/`` route, catch-all, or 404 handler keep their behavior.
        """
        try:
            endpoints = sorted({
                rule.rule for rule in current_app.url_map.iter_rules()
                if not rule.rule.startswith('/static')
            })
        except Exception:
            endpoints = []
        return jsonify({
            'error': {
                'code': 'ResourceNotFound',
                'message': (
                    f"The requested path '{request.path}' was not found on "
                    f"service '{base.service_name}'."
                ),
                'service': base.service_name,
                'availableEndpoints': endpoints,
            }
        }), 404

    return bp
