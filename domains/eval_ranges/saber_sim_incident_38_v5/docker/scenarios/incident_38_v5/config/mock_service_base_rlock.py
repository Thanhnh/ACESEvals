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

import threading
from flask import Blueprint, request, jsonify


MAX_LOGS = 10_000

# Header stamped by run_scenario.sh on every attack curl (Phase 10 live capture).
ATTACK_TECHNIQUE_HEADER = "X-Saber-Attack-Technique"


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

    return bp
