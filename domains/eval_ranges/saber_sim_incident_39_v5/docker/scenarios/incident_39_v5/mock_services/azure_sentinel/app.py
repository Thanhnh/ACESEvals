# Azure Sentinel SIEM Service — Flask routes
#
# Thin routing layer. Business logic lives in:
# - kusto_client.py  (Kusto wrapper, schema init, static seeding)
# - log_collector.py (background polling, raw buffer, analytics engine)
#
# Posture Analysis MCP endpoints (fixture-based):
# - /query_lake            (sentinel-data-exploration — EASM)
# - /fetch_attack_paths    (sentinel-purple-agent — attack paths)
# - /query_advanced_hunting (sentinel-purple-beta — exposure graph)

from flask import Flask, request, jsonify
import os
import uuid
import yaml
import threading as _threading
from datetime import datetime
from threading import Lock, Thread

from mock_service_base import MockServiceBase, create_base_blueprint
from kusto_client import (
    KustoClient,
    initialize_kusto,
    seed_static_tables,
    load_attack_corpus,
)
from log_collector import (
    RAW_LOGS,
    RAW_LOGS_LOCK,
    ANALYTICS_RULES,
    RULES_LOCK,
    INCIDENTS,
    INCIDENTS_LOCK,
    initialize_builtin_rules,
    start_collector,
    start_analytics_evaluator,
    load_historical_logs,
)

app = Flask(__name__)
base = MockServiceBase('azure-sentinel')

# ============================================
# Configuration
# ============================================

SCHEMA_PATH = os.environ.get('SCHEMA_PATH', '/app/schemas/azure_log_schemas.yaml')
STATIC_SEED_PATH = os.environ.get('STATIC_SEED_PATH', '/app/static_seed_data.yaml')
HISTORICAL_LOGS_DIR = os.environ.get('HISTORICAL_LOGS_DIR', '/app/historical-logs')
ATTACK_CORPUS_DIR = os.environ.get('ATTACK_CORPUS_DIR', '/app/attack_corpus')
KUSTO_URL = os.environ.get('KUSTO_URL', 'http://kusto-emulator:8080')
KUSTO_DATABASE = 'NetDefaultDB'

SERVICES = {
    'keyvault': os.environ.get('KEYVAULT_URL', 'https://keyvault:443'),
    'azure_ad': os.environ.get('AZURE_AD_URL', 'http://azure-ad:8080'),
    'imds': os.environ.get('IMDS_URL', 'http://imds:80'),
    'arm': os.environ.get('ARM_URL', 'https://arm-api:443'),
    'functions': os.environ.get('FUNCTIONS_URL', 'http://azure-functions:7071'),
    'eventgrid': os.environ.get('EVENTGRID_URL', 'http://eventgrid:4000'),
    'gateway': os.environ.get('GATEWAY_URL', 'http://gateway:8080'),
    'domain_controller': os.environ.get('DOMAIN_CONTROLLER_URL', 'http://domain-controller:8080'),
    'front_door': os.environ.get('FRONT_DOOR_URL', 'http://front-door:8080'),
    'aks_pod': os.environ.get('AKS_POD_URL', 'http://aks-pod:8080'),
    'kubernetes_api': os.environ.get('KUBERNETES_API_URL', 'https://kubernetes-api:443'),
    'exchange_online': os.environ.get('EXCHANGE_URL', 'https://exchange-online:443'),
    'app_service': os.environ.get('APP_SERVICE_URL', 'http://app-service:8080'),
    'windows_endpoint': os.environ.get('WINDOWS_ENDPOINT_URL', 'http://windows-endpoint:8080'),
    'lateral_movement': os.environ.get('LATERAL_MOVEMENT_URL', 'http://lateral-movement:8080'),
    'mdatp_engine': os.environ.get('MDATP_ENGINE_URL', 'http://mdatp-engine:8080'),
    'adfs_server': os.environ.get('ADFS_SERVER_URL', 'http://adfs-server:8080'),
    'c2_server': os.environ.get('C2_SERVER_URL', 'http://c2-server:8080'),
    'mcas_mtp_alerts': os.environ.get('MCAS_MTP_ALERTS_URL', 'http://mcas-mtp-alerts:8080'),
}

# Global Kusto client
kusto = KustoClient(KUSTO_URL, KUSTO_DATABASE)

# Query log buffer
QUERY_LOGS = []
QUERY_LOCK = Lock()

# ============================================
# Posture Analysis MCP — Configuration
# ============================================
# Fixture paths for the 3 posture analysis MCP tools.
# Mounted as volumes at runtime (per-scenario), not baked into the image.

EASM_FIXTURE_PATH = os.environ.get(
    'EASM_FIXTURE_PATH', '/fixtures/easm.yaml')
ATTACK_PATHS_FIXTURE_PATH = os.environ.get(
    'ATTACK_PATHS_FIXTURE_PATH', '/fixtures/attack_paths.yaml')
EXPOSURE_GRAPH_FIXTURE_PATH = os.environ.get(
    'EXPOSURE_GRAPH_FIXTURE_PATH', '/fixtures/exposure_graph.yaml')

# In-memory fixture stores (loaded at startup)
_posture_fixtures = {
    'easm': {},
    'attack_paths': {},
    'exposure_graph': {},
}

# Separate audit log for posture analysis MCP tool calls.
# SABER trajectory scorers (C0a/C0b/C0c, C8) read these to verify tool usage.
POSTURE_AUDIT_LOGS = []
POSTURE_AUDIT_LOCK = Lock()


def _load_posture_fixture(name, path, response_key):
    """Load a single posture analysis fixture YAML file."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f) or {}
        _posture_fixtures[name] = data
        rule_count = len(data.get(response_key, []))
        print(f"[POSTURE] Loaded {name} fixtures from {path}: "
              f"{rule_count} response rules", flush=True)
    except FileNotFoundError:
        print(f"[POSTURE] No fixture at {path} — {name} endpoint will return "
              f"empty responses", flush=True)
    except Exception as e:
        print(f"[POSTURE] Error loading {name} fixtures: {e}", flush=True)


def load_posture_fixtures():
    """Load all posture analysis fixture files."""
    _load_posture_fixture(
        'easm', EASM_FIXTURE_PATH, 'query_lake_responses')
    _load_posture_fixture(
        'attack_paths', ATTACK_PATHS_FIXTURE_PATH,
        'fetch_attack_paths_responses')
    _load_posture_fixture(
        'exposure_graph', EXPOSURE_GRAPH_FIXTURE_PATH,
        'query_advanced_hunting_responses')


def _match_fixture_rules(fixture_name, response_key, query_text):
    """Match query text against fixture rules using substring matching.

    Returns a list of matched response dicts.
    """
    matched = []
    for i, rule in enumerate(_posture_fixtures[fixture_name].get(response_key, [])):
        query_match = rule.get('query_match', '')
        if not query_match:
            print(f"[POSTURE] WARNING: {fixture_name} rule {i} missing "
                  f"'query_match' field — skipping", flush=True)
            continue
        if query_match.lower() in query_text:
            matched.append(rule.get('response', {}))
    return matched


def _kusto_rows(kql, limit=200):
    """Run a KQL query and return rows as a list of dicts (empty on error).

    Used by the posture-analysis MCP endpoints to serve real posture data from
    Kusto when the per-scenario fixture YAMLs are absent (the fixtures are not
    generated by the range pipeline, so without this fallback the exposure
    graph / attack-path / EASM endpoints always returned empty — even though the
    backing tables (ExposureGraphNodes/Edges, DeviceTvm*) are ingested into
    Kusto from logs/*.jsonl).
    """
    try:
        result = kusto.execute_query(f"{kql} | take {int(limit)}")
        tables = result.get('Tables', [])
        if not tables:
            return []
        primary = tables[0]
        cols = [c['ColumnName'] for c in primary.get('Columns', [])]
        if not cols:
            # No column definitions → no usable rows (a real Kusto result always
            # carries Columns alongside Rows). Avoid emitting empty-dict rows.
            return []
        return [dict(zip(cols, row)) for row in primary.get('Rows', [])]
    except Exception as e:
        print(f"[POSTURE] Kusto fallback query failed for {kql!r}: {e}", flush=True)
        return []


# ============================================
# KQL Query endpoint
# ============================================

@app.route('/query', methods=['POST'])
def query_workspace():
    """Execute KQL queries against the Kusto engine.

    Read path is OPEN (Phase 10 §0.2 Prereq A / review Finding ①). The
    SIEM-querying agents (detection-hunting / incident-investigation /
    SOC-analyst / detection-authoring) and the shared query MCP servers post
    here with **no** Authorization header; the previous Bearer gate returned
    401, so those agents read an empty SIEM no matter how much attack telemetry
    was captured — defeating the entire live-capture feature. We drop the auth
    requirement on the read path so captured telemetry is actually reachable.
    A valid scoped Bearer is still accepted (forward-compatible with the MCP
    client-token fix on feature/detection-authoring-xdr-tools, commit 567e17e8),
    so adopting that change later requires no revert here.
    """
    data = request.get_json() or {}
    query_text = data.get('query', '')
    timespan = data.get('timespan', 'PT24H')
    start_time = datetime.utcnow()

    try:
        result = kusto.execute_query(query_text)
        tables = result.get('Tables', [])
        if tables:
            primary = tables[0]
            columns = [{'name': c['ColumnName'], 'type': c['DataType']}
                       for c in primary.get('Columns', [])]
            rows = primary.get('Rows', [])
        else:
            columns, rows = [], []
        status, error = 'Success', None
    except Exception as e:
        columns, rows = [], []
        status, error = 'Failed', str(e)

    query_log = {
        'time': start_time.isoformat() + 'Z',
        'category': 'LAQueryLogs',
        'operationName': 'Query',
        'resultType': status,
        'properties': {
            'queryText': query_text,
            'timespan': timespan,
            'resultCount': len(rows),
            'durationMs': int((datetime.utcnow() - start_time).total_seconds() * 1000),
            'errorMessage': error,
        },
    }
    with QUERY_LOCK:
        QUERY_LOGS.append(query_log)
    try:
        kusto.ingest_json('LAQueryLogs', [query_log])
    except Exception:
        pass

    return jsonify({
        'tables': [{'name': 'PrimaryResult', 'columns': columns, 'rows': rows}],
        'status': status,
    })


@app.route('/workspace/tables', methods=['GET'])
def get_workspace_tables():
    """List available Kusto tables."""
    try:
        result = kusto.execute_query(".show tables")
        rows = result.get('Tables', [{}])[0].get('Rows', [])
        names = [row[0] for row in rows]
    except Exception:
        names = ['AllLogs', 'LAQueryLogs']
    return jsonify({'value': names})


# ============================================
# Raw logs endpoint (for log streamer)
# ============================================

@app.route('/logs', methods=['GET'])
def get_all_logs():
    """Get collected logs with original fields intact."""
    limit = request.args.get('limit', 1000, type=int)
    with RAW_LOGS_LOCK:
        logs = list(RAW_LOGS[-limit:])
    return jsonify({'value': logs, 'count': len(logs)})


@app.route('/logs/sources', methods=['GET'])
def get_sources():
    """Get log source counts."""
    with RAW_LOGS_LOCK:
        sources = {}
        for log in RAW_LOGS:
            src = log.get('_source', log.get('source', 'unknown'))
            sources[src] = sources.get(src, 0) + 1
    return jsonify(sources)


@app.route('/logs/operations', methods=['GET'])
def get_operations():
    """Get operation name counts (via Kusto)."""
    try:
        result = kusto.execute_query("AllLogs | summarize count() by operationName")
        rows = result.get('Tables', [{}])[0].get('Rows', [])
        ops = {row[0]: row[1] for row in rows}
    except Exception:
        ops = {}
    return jsonify(ops)


# ============================================
# Analytics rules & incidents
# ============================================

@app.route('/analytics/rules', methods=['GET'])
def get_analytics_rules():
    with RULES_LOCK:
        return jsonify({'value': ANALYTICS_RULES, 'count': len(ANALYTICS_RULES)})


@app.route('/analytics/rules', methods=['POST'])
def create_analytics_rule():
    rule = request.get_json()
    rule['id'] = str(uuid.uuid4())
    rule['created'] = datetime.utcnow().isoformat() + 'Z'
    rule['enabled'] = rule.get('enabled', True)
    with RULES_LOCK:
        ANALYTICS_RULES.append(rule)
    return jsonify(rule), 201


@app.route('/analytics/rules/<rule_id>', methods=['DELETE'])
def delete_analytics_rule(rule_id):
    with RULES_LOCK:
        ANALYTICS_RULES[:] = [r for r in ANALYTICS_RULES if r['id'] != rule_id]
    return jsonify({'status': 'deleted'}), 200


@app.route('/api/incidents', methods=['GET'])
def api_get_incidents():
    """Sentinel REST API path — requires SecurityEvents.Read scope.
    Returns 403 for tokens that lack the required scope."""
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({'error': {'code': 'Unauthorized', 'message': 'Bearer token required'}}), 401
    return jsonify({'error': {'code': 'InsufficientPermissions', 'message': 'Token does not have SecurityEvents.Read or SecurityAlert.Read scope'}}), 403


@app.route('/incidents', methods=['GET'])
def get_incidents():
    with INCIDENTS_LOCK:
        return jsonify({'value': INCIDENTS, 'count': len(INCIDENTS)})


@app.route('/incidents/<incident_id>', methods=['GET'])
def get_incident(incident_id):
    with INCIDENTS_LOCK:
        incident = next((i for i in INCIDENTS if i['id'] == incident_id), None)
    if incident:
        return jsonify(incident)
    return jsonify({'error': 'Incident not found'}), 404


# ============================================
# Posture Analysis MCP endpoints
# ============================================
# These serve fixture data for the 3 MCP tools used by the posture
# analysis agent.  Matching is intentionally simple: if the agent's
# query (serialised to JSON, lowercased) contains a rule's
# query_match string, that rule's response is included.

@app.route('/query_lake', methods=['POST'])
def query_lake():
    """EASM query — external attack surface assets (sentinel-data-exploration)."""
    body = request.get_json(force=True) or {}
    query_text = str(body.get('query', '')).lower()

    matched_assets = []
    for resp in _match_fixture_rules('easm', 'query_lake_responses', query_text):
        for value in resp.values():
            if isinstance(value, list):
                matched_assets.extend(value)
            else:
                matched_assets.append(value)

    # Fixtures absent → serve external attack-surface / vulnerability posture
    # from the DeviceTvm* tables ingested into Kusto. Only fall back for a
    # non-empty query — a blank/malformed request must not dump the table.
    if query_text and not matched_assets:
        for tbl in ('DeviceTvmSoftwareVulnerabilities',
                    'DeviceTvmSecureConfigurationAssessment',
                    'DeviceTvmSoftwareInventory'):
            matched_assets.extend(_kusto_rows(tbl, limit=100))

    log_entry = {
        'time': datetime.utcnow().isoformat() + 'Z',
        'operationName': 'EASM.QueryLake',
        'query': body,
        'resultCount': len(matched_assets),
        'resultType': 'Success' if matched_assets else 'NoResults',
    }
    with POSTURE_AUDIT_LOCK:
        POSTURE_AUDIT_LOGS.append(log_entry)

    return jsonify({
        'assets': matched_assets,
        'total_count': len(matched_assets),
        'query': body,
    })


@app.route('/fetch_attack_paths', methods=['POST'])
def fetch_attack_paths():
    """EKG query — pre-computed attack paths (sentinel-purple-agent)."""
    body = request.get_json(force=True) or {}
    query_text = str(body.get('query', '')).lower()

    matched_paths = []
    for resp in _match_fixture_rules(
            'attack_paths', 'fetch_attack_paths_responses', query_text):
        matched_paths.extend(resp.get('attack_paths', []))

    # Fixtures absent → derive attack paths from the exposure-graph edges in
    # Kusto (each edge is a source→target relationship an attacker can traverse).
    # Only fall back for a non-empty query — a blank request must not dump edges.
    if query_text and not matched_paths:
        for e in _kusto_rows('ExposureGraphEdges', limit=100):
            matched_paths.append({
                'source': e.get('SourceNodeName'),
                'source_type': e.get('SourceNodeLabel'),
                'relationship': e.get('EdgeLabel'),
                'target': e.get('TargetNodeName'),
                'target_type': e.get('TargetNodeLabel'),
                'properties': e.get('EdgeProperties'),
            })

    log_entry = {
        'time': datetime.utcnow().isoformat() + 'Z',
        'operationName': 'PurpleAgent.FetchAttackPaths',
        'query': body,
        'pathsReturned': len(matched_paths),
        'resultType': 'Success' if matched_paths else 'NoResults',
    }
    with POSTURE_AUDIT_LOCK:
        POSTURE_AUDIT_LOGS.append(log_entry)

    return jsonify({
        'attack_paths': matched_paths,
        'total_count': len(matched_paths),
        'query': body,
    })


@app.route('/query_advanced_hunting', methods=['POST'])
def query_advanced_hunting():
    """Exposure graph query — identities, permissions, relationships (sentinel-purple-beta)."""
    body = request.get_json(force=True) or {}
    query_text = str(body.get('query', '')).lower()

    matched_edges = []
    matched_nodes = []
    for resp in _match_fixture_rules(
            'exposure_graph', 'query_advanced_hunting_responses', query_text):
        matched_edges.extend(resp.get('graph_edges', []))
        matched_nodes.extend(resp.get('graph_nodes', []))

    # Fixtures absent → serve the real exposure graph (identities, permissions,
    # relationships) from the ExposureGraphNodes/Edges tables in Kusto. Only
    # fall back for a non-empty query — a blank request must not dump the graph.
    if query_text and not matched_edges and not matched_nodes:
        matched_nodes = _kusto_rows('ExposureGraphNodes', limit=200)
        matched_edges = _kusto_rows('ExposureGraphEdges', limit=200)

    log_entry = {
        'time': datetime.utcnow().isoformat() + 'Z',
        'operationName': 'PurpleBeta.QueryAdvancedHunting',
        'query': body,
        'edgesReturned': len(matched_edges),
        'nodesReturned': len(matched_nodes),
        'resultType': 'Success' if (matched_edges or matched_nodes) else 'NoResults',
    }
    with POSTURE_AUDIT_LOCK:
        POSTURE_AUDIT_LOGS.append(log_entry)

    return jsonify({
        'graph_edges': matched_edges,
        'graph_nodes': matched_nodes,
        'total_edges': len(matched_edges),
        'total_nodes': len(matched_nodes),
        'query': body,
    })


@app.route('/posture/audit/logs', methods=['GET'])
def posture_audit_logs():
    """Audit trail for posture analysis MCP tool calls.

    SABER trajectory scorers (C0a, C0b, C0c, C7, C8) read this
    endpoint to verify the agent invoked the expected tools.
    """
    with POSTURE_AUDIT_LOCK:
        logs = list(POSTURE_AUDIT_LOGS)
    return jsonify({'value': logs, 'count': len(logs)})


# ============================================
# Health extras
# ============================================

def _sentinel_health_extras():
    try:
        result = kusto.execute_query("AllLogs | count")
        log_count = result.get('Tables', [{}])[0].get('Rows', [[0]])[0][0]
    except Exception:
        log_count = 0
    with POSTURE_AUDIT_LOCK:
        posture_call_count = len(POSTURE_AUDIT_LOGS)
    return {
        'logCount': log_count,
        # Whether the startup data load (historical benign + attack corpus) has
        # finished. Agents/scorers can poll this to avoid querying a partially
        # loaded SIEM; the load is done smallest-table-first so attack/posture
        # data is queryable within seconds even before dataReady flips true.
        'dataReady': all(_LOAD_STATE.values()),
        'dataLoad': dict(_LOAD_STATE),
        'services': list(SERVICES.keys()),
        'threadCount': _threading.active_count(),
        'threads': [t.name for t in _threading.enumerate()],
        'kustoUrl': KUSTO_URL,
        'posture_mcp_tools': ['query_lake', 'fetch_attack_paths',
                              'query_advanced_hunting'],
        'posture_mcp_calls': posture_call_count,
    }


app.register_blueprint(create_base_blueprint(
    base,
    health_extras=_sentinel_health_extras,
    include_audit_logs=False,
    include_tokens=False,
))


# ============================================
# Startup
# ============================================

_started = False

# Tracks completion of the two startup data loads so /health can report
# ``dataReady``. Kept as a dict (mutated in place) so the loader wrappers don't
# need ``global``. Both loads run concurrently — the attack corpus appends to
# base tables as the historical loader creates them, so serialising them would
# delay attack telemetry behind the huge benign-noise tables.
_LOAD_STATE = {'historical': False, 'attack': False}


def start_background_threads():
    global _started
    if _started:
        return
    _started = True

    if not initialize_kusto(kusto, SCHEMA_PATH):
        print("[ERROR] Failed to initialize Kusto", flush=True)

    seed_static_tables(kusto, STATIC_SEED_PATH)

    def _run_historical():
        try:
            load_historical_logs(kusto, HISTORICAL_LOGS_DIR)
        finally:
            _LOAD_STATE['historical'] = True

    def _run_attack():
        try:
            load_attack_corpus(kusto, ATTACK_CORPUS_DIR)
        finally:
            _LOAD_STATE['attack'] = True

    # Load historical JSONL logs into Kusto (runs in background thread)
    hist_thread = Thread(target=_run_historical, daemon=True)
    hist_thread.start()

    # Load the captured attack corpus into the real tables (Phase 10 live
    # capture). Runs in its own thread; it waits for each base table (created by
    # the historical load) before appending the time-shifted attack rows. No-op
    # when ATTACK_CORPUS_DIR is absent/empty (benign-only ranges).
    attack_thread = Thread(target=_run_attack, daemon=True)
    attack_thread.start()

    initialize_builtin_rules()

    start_collector(kusto, SERVICES)
    start_analytics_evaluator(kusto)

    # Load posture analysis MCP fixture data (no-op if files absent)
    load_posture_fixtures()

    print("[INIT] Starting Azure Sentinel SIEM service with Kusto Emulator", flush=True)
    print(f"[INIT] Polling services: {list(SERVICES.keys())}", flush=True)
    print("[INIT] Posture analysis MCP endpoints: /query_lake, "
          "/fetch_attack_paths, /query_advanced_hunting", flush=True)


start_background_threads()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, use_reloader=False, threaded=True)
