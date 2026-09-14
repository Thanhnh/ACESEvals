# Kusto Emulator Client — Schema loading, table creation, query/ingest
#
# Wraps the Kusto Emulator REST API and handles:
# - Schema loading from azure_log_schemas.yaml
# - Table creation from schema definitions
# - KQL query execution
# - JSON record ingestion
# - Static seed data loading

import json
import os
import time

import requests
import yaml


KUSTO_RESERVED = {'time', 'timestamp', 'level', 'type', 'source'}


class KustoClient:
    """Client for Kusto Emulator REST API."""

    def __init__(self, endpoint, database):
        self.endpoint = endpoint.rstrip('/')
        self.database = database
        self.mgmt_url = f"{self.endpoint}/v1/rest/mgmt"
        self.query_url = f"{self.endpoint}/v1/rest/query"

    def execute_mgmt_command(self, command):
        """Execute a Kusto management command."""
        payload = {"db": self.database, "csl": command}
        try:
            resp = requests.post(self.mgmt_url, json=payload, timeout=30)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            print(f"[KUSTO] Management command error: {e}", flush=True)
            raise

    def execute_query(self, query):
        """Execute a KQL query."""
        payload = {"db": self.database, "csl": query}
        try:
            resp = requests.post(self.query_url, json=payload, timeout=30)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            print(f"[KUSTO] Query error: {e}", flush=True)
            raise

    def ingest_json(self, table_name, records):
        """Ingest JSON records into a table using .ingest inline."""
        if not records:
            return
        json_data = '\n'.join(json.dumps(r) for r in records)
        command = (
            f".ingest inline into table {table_name} "
            f"with (format='multijson') <|\n{json_data}"
        )
        try:
            self.execute_mgmt_command(command)
        except Exception as e:
            print(f"[KUSTO] Ingest error for {table_name}: {e}", flush=True)


# ============================================
# Schema helpers
# ============================================

def load_schemas(schema_path):
    """Load Azure log schemas from YAML (single source of truth)."""
    try:
        with open(schema_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"[KUSTO] Warning: Could not load schemas from {schema_path}: {e}", flush=True)
        return {}


def infer_kusto_type(value):
    """Infer Kusto column type from a Python value."""
    if value is None:
        return 'string'
    if isinstance(value, bool):
        return 'bool'
    if isinstance(value, int):
        return 'long'
    if isinstance(value, float):
        return 'real'
    if isinstance(value, (dict, list)):
        return 'dynamic'
    return 'string'


def _infer_kusto_type_from_schema(field_type):
    """Map schema field type string to Kusto type."""
    type_map = {
        'datetime': 'string',
        'string': 'string',
        'integer': 'long',
        'int': 'long',
        'guid': 'string',
        'object': 'dynamic',
        'array': 'dynamic',
        'float': 'real',
        'boolean': 'bool',
    }
    return type_map.get(field_type, 'string')


def _generate_table_from_example(table_name, example_json):
    """Generate CREATE TABLE from an example JSON dict."""
    columns = []
    seen = set()
    for field_name, field_value in example_json.items():
        if field_name in seen:
            continue
        seen.add(field_name)
        col = f'["{field_name}"]' if field_name in KUSTO_RESERVED else field_name
        columns.append(f'{col}: {infer_kusto_type(field_value)}')
    # ``AttackTechnique`` is the Phase 10 live-capture tag stamped by the mocks
    # (mock_service_base.append_log). It must be a real column or the
    # ``.ingest inline`` drops it, leaving captured attack rows untagged.
    for extra in ('source', 'collectedAt', 'AttackTechnique'):
        if extra not in seen:
            columns.append(f'{extra}: string')
    return f'.create table {table_name} ({", ".join(columns)})'


def generate_table_command(table_name, schema):
    """Generate CREATE TABLE command from a schema definition."""
    example_str = schema.get('example', '')
    if example_str:
        try:
            return _generate_table_from_example(table_name, json.loads(example_str))
        except json.JSONDecodeError as e:
            print(f"[KUSTO] Warning: Bad example JSON for {table_name}: {e}", flush=True)

    fields = schema.get('fields', [])
    if not fields:
        return _generic_table_command(table_name)

    columns, seen = [], set()
    for field in fields:
        name = field.get('name', '')
        if '.' in name:
            parent = name.split('.')[0]
            if parent not in seen:
                col = f'["{parent}"]' if parent in KUSTO_RESERVED else parent
                columns.append(f'{col}: dynamic')
                seen.add(parent)
            continue
        col = f'["{name}"]' if name in KUSTO_RESERVED else name
        if name not in seen:
            columns.append(f'{col}: {_infer_kusto_type_from_schema(field.get("type", "string"))}')
            seen.add(name)
    for extra in ('source', 'collectedAt', 'AttackTechnique'):
        if extra not in seen:
            columns.append(f'{extra}: string')
    return f'.create table {table_name} ({", ".join(columns)})'


def _generic_table_command(table_name):
    return (
        f'.create table {table_name} '
        f'(["time"]: string, category: string, operationName: string, '
        f'resultType: string, properties: dynamic, source: string, '
        f'collectedAt: string, AttackTechnique: string)'
    )


# ============================================
# Initialization
# ============================================

# Schema key → Kusto table name
SCHEMA_TO_TABLE = {
    'key_vault_audit_event': 'AzureKeyVaultAuditLogs',
    'sign_in_log': 'AADSignInLogs',
    'azure_activity_log': 'AzureActivity',
    'imds_access_log': 'InstanceMetadata',
    'function_app_log': 'FunctionAppLogs',
    'app_service_http_logs': 'AppServiceHTTPLogs',
    'front_door_access_log': 'FrontDoorAccessLog',
    'nsg_flow_log': 'NetworkSecurityGroupFlowEvent',
    'exchange_online_audit_log': 'OfficeActivity',
    'container_logs': 'ContainerLogs',
    'kube_audit_logs': 'KubeAuditLogs',
    'device_info': 'DeviceInfo',
    'easm_asset': 'ExternalAttackSurfaceInsight',
    'attack_path': 'AttackPathResult',
    'tenant_config': 'TenantConfig',
    'threat_intel_indicators': 'ThreatIntelIndicators',
    'exposure_graph_nodes': 'ExposureGraphNodes',
    'exposure_graph_edges': 'ExposureGraphEdges',
    'identity_info': 'IdentityInfo',
    'behavior_analytics': 'BehaviorAnalytics',
    'user_peer_analytics': 'UserPeerAnalytics',
    'email_events': 'EmailEvents',
    'email_url_info': 'EmailUrlInfo',
    'office_activity': 'OfficeActivity',
    'cloud_app_events': 'CloudAppEvents',
}

EXTRA_TABLES = [
    'SecurityEvent', 'SysmonEvent', 'SQLSecurityAuditEvents',
    'NetworkSecurityGroupFlowEvent', 'ManagedIdentityToken', 'AllLogs',
    'KubeAuditLogs', 'ContainerLogs', 'OfficeActivity',
]


def initialize_kusto(kusto, schema_path):
    """Create all tables in Kusto from schema definitions.

    Returns True if at least one table was created.
    """
    print("[KUSTO] Initializing Kusto Emulator", flush=True)

    # Wait for Kusto readiness
    for i in range(30):
        try:
            requests.get(f"{kusto.endpoint}/v1/rest/mgmt", timeout=5)
            print("[KUSTO] Kusto Emulator is ready", flush=True)
            break
        except Exception:
            if i == 29:
                print("[KUSTO] ERROR: Kusto not available after 30 retries", flush=True)
                return False
            time.sleep(1)

    schemas = load_schemas(schema_path)
    tables = {}

    for schema_key, table_name in SCHEMA_TO_TABLE.items():
        if schema_key in schemas:
            tables[table_name] = generate_table_command(table_name, schemas[schema_key])
            print(f"[KUSTO] Generated schema for {table_name} from {schema_key}", flush=True)
        else:
            tables[table_name] = _generic_table_command(table_name)

    # Data-driven tables: any schema block that names its Kusto table via a
    # ``table:`` field is auto-created with its real columns. This lets the full
    # Sentinel/Defender table universe (Phase 10 §9.0) be added by dropping a
    # schema block in azure_log_schemas.yaml — no SCHEMA_TO_TABLE edit needed.
    for schema_key, schema_def in schemas.items():
        if not isinstance(schema_def, dict):
            continue
        tbl = schema_def.get('table')
        if tbl and tbl not in tables:
            tables[tbl] = generate_table_command(tbl, schema_def)
            print(f"[KUSTO] Generated schema for {tbl} from {schema_key} (table-keyed)", flush=True)

    # Defender XDR Advanced Hunting tables (Phase 10 §3b-F): created from the
    # xdr_translate exemplar records so the dual-emit has real, correctly-shaped
    # destination tables. Each gains an AttackTechnique column via
    # _generate_table_from_example (capture tag survives ingest).
    try:
        from xdr_translate import AH_TABLE_SCHEMAS as _AH_SCHEMAS
        for ah_table, example in _AH_SCHEMAS.items():
            if ah_table not in tables:
                tables[ah_table] = _generate_table_from_example(ah_table, example)
                print(f"[KUSTO] Generated AH schema for {ah_table} (XDR dual-emit)", flush=True)
    except Exception as e:  # pragma: no cover - module present in the image
        print(f"[KUSTO] XDR AH tables not created: {e}", flush=True)

    for name in EXTRA_TABLES:
        if name not in tables:
            tables[name] = _generic_table_command(name)

    created = 0
    for table_name, cmd in tables.items():
        try:
            print(f"[KUSTO] Creating {table_name}: {cmd[:80]}...", flush=True)
            kusto.execute_mgmt_command(cmd)
            print(f"[KUSTO] {table_name} table created successfully", flush=True)
            created += 1
        except Exception as e:
            if "already exists" in str(e) or "400" in str(e):
                created += 1
            else:
                print(f"[KUSTO] Error creating {table_name}: {e}", flush=True)
        time.sleep(0.2)

    ok = created >= 1
    print(f"[KUSTO] Initialization {'complete' if ok else 'FAILED'} "
          f"({created}/{len(tables)} tables ready)", flush=True)
    return ok


def seed_static_tables(kusto, seed_path):
    """Seed static reference tables (DeviceInfo, TenantConfig, etc.)."""
    print("[KUSTO] Seeding static tables from YAML...", flush=True)
    try:
        with open(seed_path, 'r') as f:
            seed_data = yaml.safe_load(f) or {}
    except Exception as e:
        print(f"[KUSTO] ERROR loading static seed data: {e}", flush=True)
        return
    for table_name, records in seed_data.items():
        if not records:
            continue
        try:
            kusto.ingest_json(table_name, records)
            print(f"[KUSTO] Seeded {table_name}: {len(records)} records", flush=True)
        except Exception as e:
            print(f"[KUSTO] Error seeding {table_name}: {e}", flush=True)


def load_attack_corpus(kusto, corpus_dir):
    """Load the captured attack corpus into the REAL telemetry tables.

    The eval SIEM is benign-only (no run_scenario.sh at eval time). The captured
    attack rows (``<corpus_dir>/<Table>.json``, produced by
    ``saber-sim generate-attack-corpus``) are time-shifted so the newest lands at
    ≈now (so ago()/time-window KQL fires) and appended to the real ``<Table>``
    (created by the historical load). No-op if the dir is absent/empty.
    Ported from feature/aarti/detection-authoring-agent (Phase 10 live capture).
    """
    if not corpus_dir or not os.path.isdir(corpus_dir):
        print(f"[KUSTO] No attack corpus at {corpus_dir} — attack telemetry skipped",
              flush=True)
        return
    files = [f for f in os.listdir(corpus_dir) if f.endswith('.json')]
    if not files:
        print(f"[KUSTO] Attack corpus dir empty ({corpus_dir})", flush=True)
        return

    from datetime import datetime, timezone

    try:
        from timeshift import compute_shift_seconds, record_max_dt, shift_record
    except Exception as e:  # pragma: no cover - module present in the image
        print(f"[KUSTO] timeshift unavailable — attack corpus not shifted: {e}", flush=True)
        compute_shift_seconds = record_max_dt = shift_record = None

    # Pass 1: read all rows, find the global-max timestamp for a single shift.
    table_rows = {}
    global_max = None
    for fname in files:
        try:
            with open(os.path.join(corpus_dir, fname)) as f:
                rows = json.load(f) or []
        except Exception as e:
            print(f"[KUSTO] Error reading attack {fname}: {e}", flush=True)
            continue
        table_rows[fname[:-len('.json')]] = rows
        if record_max_dt:
            for r in rows:
                dt = record_max_dt(r)
                if dt and (global_max is None or dt > global_max):
                    global_max = dt
    shift = (compute_shift_seconds(global_max, datetime.now(timezone.utc))
             if compute_shift_seconds else 0.0)

    # Pass 2: per table, wait for the (lazily-created) base table, shift + ingest.
    for table, rows in table_rows.items():
        if not rows:
            continue
        base_ready = False
        for _ in range(90):
            try:
                kusto.execute_query(f"{table} | take 1")
                base_ready = True
                break
            except Exception:
                time.sleep(2)
        if not base_ready:
            print(f"[KUSTO] Attack {table}: base table never appeared — skipped", flush=True)
            continue
        try:
            if shift and shift_record:
                for r in rows:
                    shift_record(r, shift)
            kusto.ingest_json(table, rows)
            print(f"[KUSTO] Attack corpus {table}: {len(rows)} rows "
                  f"(shift +{shift / 3600:.1f}h)", flush=True)
        except Exception as e:
            print(f"[KUSTO] Error loading attack {table}: {e}", flush=True)
