# Log Collector — Background threads for polling and analytics
#
# Handles:
# - Loading historical JSONL logs into Kusto at startup
# - Polling mock services for audit logs
# - Maintaining the RAW_LOGS buffer (preserves original fields)
# - Routing logs to Kusto tables by category/source
# - Evaluating analytics rules and creating incidents

import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock, Thread

import requests

# Timestamp normalization (Phase 10 live capture). Bundle/captured logs are
# stamped at generation/capture time; on a later container start, KQL ago()
# windows would filter them all out. timeshift forwards every record by ONE
# global delta so the newest event lands at ≈now while preserving relative
# spacing (correlation windows stay valid). Optional import so the collector
# still runs if the module is absent.
try:
    from timeshift import compute_shift_seconds, record_max_dt, shift_record
    _TIMESHIFT_AVAILABLE = True
except Exception:  # pragma: no cover - module always present in the image
    _TIMESHIFT_AVAILABLE = False

# Defender XDR dual-emit (Phase 10 §3b-F). Sentinel rows we ingest are ALSO
# reshaped into Defender Advanced Hunting tables (AADSignInEventsBeta,
# EmailEvents, UrlClickEvents, CloudAppEvents) so SIEM-querying agents built
# against Defender — not just Sentinel — find the same attack events. Pure
# translation at the ingest chokepoint; preserves the AttackTechnique capture
# tag. Optional import so the collector still runs if the module is absent.
try:
    import xdr_translate as _XDR
    _XDR_AVAILABLE = True
except Exception:  # pragma: no cover - module present in the image
    _XDR = None
    _XDR_AVAILABLE = False


def _dual_emit_xdr(kusto, sentinel_table, records):
    """Reshape Sentinel ``records`` into Defender AH tables and ingest them too.

    No-op when the xdr module is unavailable. Groups translated rows by AH table
    for batch ingest. Never raises — a translation failure must not break the
    primary Sentinel ingest. The ``AttackTechnique`` tag is carried through by
    ``xdr_translate.translate_record`` so captured AH rows stay attack-tagged.
    """
    if not _XDR_AVAILABLE or _XDR is None:
        return
    try:
        buckets: dict = {}
        for rec in records:
            for ah_table, ah_rec in _XDR.translate_record(sentinel_table, rec):
                buckets.setdefault(ah_table, []).append(ah_rec)
        for ah_table, ah_records in buckets.items():
            kusto.ingest_json(ah_table, ah_records)
    except Exception as e:  # noqa: BLE001
        print(f"[XDR] dual-emit error for {sentinel_table}: {e}", flush=True)



# ============================================
# Raw log buffer
# ============================================

RAW_LOGS = []
RAW_LOGS_LOCK = Lock()
MAX_RAW_LOGS = 50000

# Deduplication: track seen log IDs to avoid re-collecting
# logs that mock services return on every poll cycle.
_SEEN_IDS = set()
_SEEN_IDS_LOCK = Lock()
_MAX_SEEN_IDS = 200000


def _log_fingerprint(log):
    """Compute a stable fingerprint for deduplication.

    Uses the log's 'Id' field if present (AAD logs), otherwise falls back
    to 'correlationId', or a SHA-256 of the content-bearing fields.
    """
    log_id = log.get('Id') or log.get('id')
    if log_id:
        return log_id
    corr = log.get('correlationId')
    if corr:
        op = log.get('operationName', '')
        rid = log.get('resourceId', '')
        t = log.get('time', '')
        return f"{corr}:{op}:{rid}:{t}"
    # Fallback: hash everything except collector-added fields
    stable = {k: v for k, v in log.items()
              if k not in ('_source', 'source', 'collectedAt')}
    raw = json.dumps(stable, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


# ============================================
# Analytics state
# ============================================

ANALYTICS_RULES = []
RULES_LOCK = Lock()
INCIDENTS = []
INCIDENTS_LOCK = Lock()

# ============================================
# Source → Kusto table mapping
# ============================================

SOURCE_TO_TABLE = {
    'keyvault': 'AzureKeyVaultAuditLogs',
    'azure_ad': 'AADSignInLogs',
    'aks_pod': 'ContainerLogs',
    'exchange_online': 'OfficeActivity',
    'imds': 'InstanceMetadata',
    'arm': 'AzureActivity',
    'azure_functions': 'FunctionAppLogs',
    'functions': 'FunctionAppLogs',          # poll key is 'functions' (was unmapped → AllLogs)
    'app_service': 'AppServiceHTTPLogs',     # SAP/web portal HTTP access (T1213, App Service)
    'kubernetes_api': 'KubeAuditLogs',
    'front_door': 'FrontDoorAccessLog',
    'gateway': 'NetworkSecurityGroupFlowEvent',
    # Attack-telemetry sources (Phase 10 §9.9) — previously fell through to AllLogs.
    # Multi-table sources (windows_endpoint) route per-row via the Type field;
    # the entry here is only a last-resort fallback when Type is absent.
    'windows_endpoint': 'DeviceProcessEvents',
    'domain_controller': 'SecurityEvent',
    'adfs_server': 'SecurityEvent',
    'eventgrid': 'EventGridPublishLogs',
    # Coordinator attack services: lateral movement (host→host auth) lands in the
    # remote-logon table; C2 beaconing (outbound callback) in the network table.
    'lateral_movement': 'DeviceLogonEvents',
    'c2_server': 'DeviceNetworkEvents',
}

CATEGORY_TO_TABLE = {
    'AuditEvent': 'AzureKeyVaultAuditLogs',
    'AzureKeyVaultAuditLogs': 'AzureKeyVaultAuditLogs',
    'SignInLogs': 'AADSignInLogs',
    'AADSignInLogs': 'AADSignInLogs',
    # Service-principal (app) sign-ins land in their own table — the faithful
    # artifact of an app-token use (T1528). Keyed by Category so the SP
    # client_credentials sign-in routes here, not the interactive sign-in table.
    'AADServicePrincipalSignInLogs': 'AADServicePrincipalSignInLogs',
    'ServicePrincipalSignInLogs': 'AADServicePrincipalSignInLogs',
    # Entra ID directory audit ops (user/SP/role/credential/device management:
    # T1087.004, T1098.x, T1136.003, …) emit Category:"AuditLogs" and belong in
    # the real Sentinel AuditLogs table — NOT the sign-in table the source
    # fallback would otherwise pick (Phase 10 §6 P2).
    'AuditLogs': 'AuditLogs',
    'Administrative': 'AzureActivity',
    'AzureActivity': 'AzureActivity',
    'InstanceMetadata': 'InstanceMetadata',
    'FunctionAppLogs': 'FunctionAppLogs',
    'FrontDoorAccessLog': 'FrontDoorAccessLog',
    'NetworkSecurityGroupFlowEvent': 'NetworkSecurityGroupFlowEvent',
    'OfficeActivity': 'OfficeActivity',
    'ExchangeItem': 'OfficeActivity',
    'ContainerLogs': 'ContainerLogs',
    'KubeAuditLogs': 'KubeAuditLogs',
    'kube-audit': 'KubeAuditLogs',
    'DeviceInfo': 'DeviceInfo',
    'ExternalAttackSurfaceInsight': 'ExternalAttackSurfaceInsight',
    'AttackPathResult': 'AttackPathResult',
    'TenantConfig': 'TenantConfig',
    # Attack-telemetry categories (Phase 10 §9.9).
    'SecurityEvent': 'SecurityEvent',
    'EventGridLogs': 'EventGridPublishLogs',
}

# Mock-table → real Sentinel/Defender-table aliases (Phase 10.2 expand/contract
# migration). A live row routed to a fabricated mock table name is ALSO written
# to its real table, so BOTH names are queryable during the transition:
#   * legacy readers (existing detections, agent prompts) keep hitting the mock
#     name without breaking, and
#   * new agents built against the strict real schema find the same telemetry.
# Benign rows are already dual-populated (ranges ship both <mock>.jsonl and
# <real>.jsonl), so this only fans out the LIVE attack rows. Phase 10.3 removes
# the mock tables and repoints every reader — see
# implementation/phase10_3_strict_schema_reconciliation.md.
# NOTE: keep this map to entries with a *genuine* real counterpart. Most other
# routing destinations already use the real name (OfficeActivity, AzureActivity,
# FunctionAppLogs, FrontDoorAccessLog, AuditLogs, EventGridPublishLogs, …) or are
# mock-only with no real equivalent (InstanceMetadata, AllLogs, AttackPathResult,
# TenantConfig) and so must NOT be aliased.
TABLE_ALIASES = {
    'AADSignInLogs': 'SigninLogs',
}

# Sources whose /audit/logs entries are alerts (one mock alert → SecurityAlert +
# AlertInfo + AlertEvidence rows). Handled specially in the ingest loop.
_ALERT_SOURCES = {'mdatp_engine', 'mcas_mtp_alerts'}

# Known Defender/Sentinel table names that may appear verbatim in a row's
# ``Type`` field (the canonical Defender column that names its own table).
_TYPE_ROUTABLE = {
    'DeviceProcessEvents', 'DeviceNetworkEvents', 'DeviceFileEvents',
    'DeviceRegistryEvents', 'DeviceImageLoadEvents', 'DeviceLogonEvents',
    'DeviceEvents', 'SecurityEvent', 'SecurityAlert', 'AlertInfo',
    'AlertEvidence', 'IdentityLogonEvents', 'IdentityDirectoryEvents',
    'CloudAppEvents', 'OfficeActivity', 'EmailEvents', 'EmailAttachmentInfo',
}


def get_table_for_log(log):
    """Determine target Kusto table from a log entry.

    Priority: explicit ``Type`` column (real Defender table name, set by the
    endpoint emitter) → ``category`` → ``source``. This routes attack telemetry
    to its real table instead of the ``AllLogs`` catch-all (Phase 10 §9.9).
    """
    t = log.get('Type')
    if t and (t in _TYPE_ROUTABLE or t in TABLE_SCHEMAS):
        return t
    category = log.get('category') or log.get('Category') or ''
    if category:
        table = CATEGORY_TO_TABLE.get(category)
        if table:
            return table
    source = log.get('source', '') or log.get('_source', '')
    return SOURCE_TO_TABLE.get(source, 'AllLogs')


# ============================================
# Schema learning + coercion (Phase 10 §9.9)
# ============================================
# Benign historical jsonl rows match the real Defender/Sentinel column schemas.
# At startup we learn each table's column set + typed defaults from those rows,
# then coerce the sparse / differently-shaped attack rows emitted live by the
# mock services to the SAME shape — so an agent's `| project <Col>` /
# `isnotempty(<Col>)` hunt sees attack rows with the table's real columns.
TABLE_SCHEMAS = {}    # table -> ordered list of real column names
TABLE_DEFAULTS = {}   # table -> {column: typed default}

_COLLECTOR_META = ('_source', 'collectedAt', 'AttackTechnique')


def _typed_default(value):
    """Pick a type-consistent empty default mirroring real Defender rows."""
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return 0
    if isinstance(value, float):
        return 0.0
    if isinstance(value, (dict, list)):
        return None
    return ""  # strings (and JSON null) → empty string, as in the captured rows


def _learn_schema(table, record):
    """Record a table's column set + typed defaults from a benign sample row."""
    cols = TABLE_SCHEMAS.setdefault(table, [])
    defs = TABLE_DEFAULTS.setdefault(table, {})
    for k, v in record.items():
        if k in _COLLECTOR_META:
            continue
        if k not in defs:
            cols.append(k)
            defs[k] = _typed_default(v)
        elif defs[k] == "" and v not in (None, ""):
            defs[k] = _typed_default(v)  # upgrade once a typed value is seen


def _now_iso():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def coerce_to_schema(record, table):
    """Reshape an attack row to the target table's learned column schema.

    Keeps matching columns, fills missing columns with typed defaults, and folds
    unknown keys into ``AdditionalFields`` (JSON string) like real Defender rows.
    Stamps ``Type`` + ``TenantId``. Minimal-stamp no-op for tables with no
    learned baseline.
    """
    cols = TABLE_SCHEMAS.get(table)
    if not cols:
        record.setdefault('Type', table)
        return record
    defs = TABLE_DEFAULTS[table]
    out, extras = {}, {}
    for k, v in record.items():
        if k in _COLLECTOR_META:
            out[k] = v
        elif k in defs:
            out[k] = v
        else:
            extras[k] = v
    for col in cols:
        if col not in out:
            out[col] = defs[col]
    if extras and 'AdditionalFields' in defs:
        existing = out.get('AdditionalFields') or ''
        try:
            base = json.loads(existing) if existing else {}
            if not isinstance(base, dict):
                base = {}
        except Exception:
            base = {}
        base.update({k: str(v) for k, v in extras.items()})
        out['AdditionalFields'] = json.dumps(base)
    out['Type'] = table
    if 'TenantId' in defs and not out.get('TenantId'):
        out['TenantId'] = os.environ.get('TENANT_ID') or defs.get('TenantId') or ''
    return out


def _flatten_security_event(record):
    """Flatten a domain-controller / ADFS event into the flat SecurityEvent shape.

    Mock DC events nest the real columns under ``properties`` (+ ``EventData``);
    the real SecurityEvent table is flat. Lift them to the top level.
    """
    props = record.get('properties')
    if not isinstance(props, dict):
        return record
    out = {k: v for k, v in record.items() if k != 'properties'}
    for k, v in props.items():
        if k == 'EventData' and isinstance(v, dict):
            for ek, ev in v.items():
                out.setdefault(ek, ev)
        else:
            out.setdefault(k, v)
    out.setdefault('Type', 'SecurityEvent')
    return out


def _expand_alert(alert):
    """Transform a mock alert dict → SecurityAlert + AlertInfo + AlertEvidence rows.

    Returns a list of ``(table, row)`` tuples. The mock emits a camelCase
    ``{alertId, title, severity, category, mitreTechnique, evidence{...}}`` shape;
    the real alert tables use different PascalCase columns, so we remap rather
    than ingest the mock shape verbatim.
    """
    aid = alert.get('alertId') or alert.get('id') or str(uuid.uuid4())
    title = alert.get('title') or alert.get('name') or 'Alert'
    sev = (alert.get('severity') or 'Medium')
    sev = sev[:1].upper() + sev[1:].lower() if sev else 'Medium'
    cat = alert.get('category') or ''
    tech = alert.get('mitreTechnique') or alert.get('mitre') or ''
    ts = alert.get('timestamp') or _now_iso()
    dev = alert.get('deviceName') or ''
    user = alert.get('user') or ''
    ev = alert.get('evidence') if isinstance(alert.get('evidence'), dict) else {}
    # Capture tag: the mdatp evaluator copies the source event's AttackTechnique
    # onto the alert; carry it onto every expanded row so tag-authoritative
    # capture snapshots the SecurityAlert (else the alert is untagged → dropped).
    atk = alert.get('AttackTechnique') or tech
    is_cloud = alert.get('_source') == 'mcas_mtp_alerts'
    provider = 'MCAS' if is_cloud else 'MDATP'
    product = 'Microsoft Defender for Cloud Apps' if is_cloud else 'Microsoft Defender for Endpoint'
    svc_source = product
    detection = 'Cloud App Security' if is_cloud else 'EDR'

    security_alert = {
        'TimeGenerated': ts, 'StartTime': ts, 'EndTime': ts, 'Timestamp': ts,
        'AlertName': title, 'DisplayName': title, 'Title': title,
        'AlertSeverity': sev, 'Description': alert.get('description') or title,
        'ProviderName': provider, 'ProductName': product,
        'SystemAlertId': aid, 'AlertId': aid,
        'Techniques': tech, 'Status': 'New', 'IsIncident': False,
        'CompromisedEntity': dev or user,
        'Entities': json.dumps(
            ([{'Type': 'host', 'HostName': dev}] if dev else []) +
            ([{'Type': 'account', 'Name': user}] if user else [])
        ),
        'ExtendedProperties': json.dumps(ev),
        'AttackTechnique': atk,
    }
    alert_info = {
        'TimeGenerated': ts, 'Timestamp': ts, 'AlertId': aid, 'Title': title,
        'Category': cat, 'Severity': sev, 'AttackTechniques': tech,
        'DetectionSource': detection, 'ServiceSource': svc_source,
        'AttackTechnique': atk,
    }
    alert_evidence = {
        'TimeGenerated': ts, 'Timestamp': ts, 'AlertId': aid, 'Title': title,
        'Severity': sev, 'AttackTechniques': tech,
        'DetectionSource': detection, 'ServiceSource': svc_source,
        'Categories': cat, 'DeviceName': dev,
        'AttackTechnique': atk,
    }
    if ev.get('fileName'):
        alert_evidence['FileName'] = ev['fileName']
        alert_evidence['EntityType'] = 'File'
        alert_evidence['EvidenceRole'] = 'Related'
    if ev.get('accountName') or user:
        alert_evidence['AccountName'] = ev.get('accountName') or user
        alert_evidence.setdefault('EntityType', 'User')
    if ev.get('commandLine'):
        alert_evidence['ProcessCommandLine'] = ev['commandLine']
    return [
        ('SecurityAlert', security_alert),
        ('AlertInfo', alert_info),
        ('AlertEvidence', alert_evidence),
    ]



# ============================================
# Historical JSONL ingestion
# ============================================

# JSONL filename (without .jsonl) → Kusto table name
FILE_TO_TABLE = {
    'AADSignInLogs': 'AADSignInLogs',
    'AppServiceHTTPLogs': 'AppServiceHTTPLogs',  # App Service HTTP logs are their own real table (not FunctionAppLogs)
    'AzureActivityLogs': 'AzureActivity',
    'AzureFunctionLogs': 'FunctionAppLogs',
    'AzureIMDSAccessLogs': 'InstanceMetadata',
    'AzureKeyVaultAuditLogs': 'AzureKeyVaultAuditLogs',
    'AzureNetworkSecurityGroupLogs': 'NetworkSecurityGroupFlowEvent',
    'EventGridPublishLogs': 'EventGridPublishLogs',
    'SQLSecurityAuditEvents': 'SQLSecurityAuditEvents',
    'StorageBlobLogs': 'StorageBlobLogs',
    'SysmonEvents': 'SysmonEvent',
    'WindowsSecurityEvents': 'SecurityEvent',
    'OfficeActivity': 'OfficeActivity',
    'ThreatIntelIndicators': 'ThreatIntelIndicators',
    'ExposureGraphNodes': 'ExposureGraphNodes',
    'ExposureGraphEdges': 'ExposureGraphEdges',
    'IdentityInfo': 'IdentityInfo',
    'BehaviorAnalytics': 'BehaviorAnalytics',
    'UserPeerAnalytics': 'UserPeerAnalytics',
    'EmailEvents': 'EmailEvents',
    'EmailUrlInfo': 'EmailUrlInfo',
    'CloudAppEvents': 'CloudAppEvents',
}

# Files to skip during historical load (metadata, transcripts, etc.)
SKIP_FILES = {'_metadata.json', 'UnknownLogs.jsonl', 'tool_calls.jsonl',
              'transcript.txt', 'guardrail_denials.jsonl'}

INGEST_BATCH_SIZE = 500


def load_historical_logs(kusto, logs_dir):
    """Load historical JSONL files into Kusto.

    Called once at startup. Reads every *.jsonl file in logs_dir, maps it
    to a Kusto table, and ingests in batches. Historical logs are NOT
    added to RAW_LOGS — that buffer is reserved for real-time data from
    the collector, so the /logs endpoint reflects live activity.
    """
    logs_path = Path(logs_dir)
    if not logs_path.is_dir():
        print(f"[HISTORICAL] No logs directory at {logs_dir}, skipping", flush=True)
        return

    # Ingest smallest files first. The attack-relevant + posture tables
    # (attack-corpus targets, ExposureGraph, DeviceTvm*, Alert*, sign-in
    # samples) are all tiny (tens of rows) while the benign background-noise
    # tables are huge (KeyVault ~64k, AzureActivity ~39k, IMDS ~36k rows).
    # Alphabetical order loaded the huge tables first, so the small tables the
    # agents actually query weren't queryable until ~2 min into boot. Loading
    # smallest-first makes the meaningful data ready within seconds; the benign
    # bulk trickles in afterward (readiness gap fix — eval review Finding).
    jsonl_files = sorted(logs_path.glob('*.jsonl'), key=lambda p: p.stat().st_size)
    if not jsonl_files:
        print(f"[HISTORICAL] No JSONL files in {logs_dir}", flush=True)
        return

    print(f"[HISTORICAL] Loading historical logs from {logs_dir} "
          f"({len(jsonl_files)} files)...", flush=True)

    total_ingested = 0

    # Pass 1: find the GLOBAL max timestamp across all ingestible files, then
    # compute one shift so the newest event lands at ≈now (Phase 10 live
    # capture). One global delta keeps relative spacing intact across tables.
    shift_seconds = 0.0
    if _TIMESHIFT_AVAILABLE:
        global_max = None
        for filepath in jsonl_files:
            if filepath.name in SKIP_FILES:
                continue
            try:
                with open(filepath, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        dt = record_max_dt(rec)
                        if dt and (global_max is None or dt > global_max):
                            global_max = dt
            except Exception:
                continue
        shift_seconds = compute_shift_seconds(global_max, datetime.now(timezone.utc))
        if shift_seconds:
            print(f"[HISTORICAL] Shifting timestamps +{shift_seconds / 3600:.1f}h "
                  f"so newest event lands at ≈now (ago() windows fire)", flush=True)

    for filepath in jsonl_files:
        fname = filepath.name
        if fname in SKIP_FILES:
            continue

        stem = filepath.stem  # filename without .jsonl
        # Identity fallback: a jsonl whose stem isn't explicitly mapped ingests
        # into a same-named Kusto table. Combined with schema-block table
        # auto-creation, this lets any universe table (Phase 10 §9.0) be served
        # by dropping logs/<Table>.jsonl — no FILE_TO_TABLE edit needed.
        table_name = FILE_TO_TABLE.get(stem, stem)
        if not table_name:
            print(f"[HISTORICAL] Skipping unknown file: {fname}", flush=True)
            continue

        try:
            batch = []
            file_count = 0
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    # Forward-shift stale timestamps so ago()/time-window KQL
                    # fires (Phase 10 live capture). Done before schema-learning
                    # + ingest so the learned defaults and the served rows agree.
                    if shift_seconds:
                        shift_record(record, shift_seconds)

                    # Tag with _source for raw buffer routing
                    if '_source' not in record:
                        record['_source'] = stem

                    # SecurityEvent: the benign DC baseline nests the real
                    # columns under ``properties`` (+ ``EventData``), but the
                    # REAL Sentinel SecurityEvent table is flat (EventID is a
                    # top-level column). The live attack-ingest path already
                    # flattens; flatten the baseline too so the learned schema is
                    # flat and benign + attack rows agree (else a top-level
                    # EventID query — and the attack-telemetry EventID marker —
                    # never match, and live flat rows get their columns dropped).
                    if table_name == 'SecurityEvent':
                        record = _flatten_security_event(record)

                    # Learn the table's real column schema from benign rows so
                    # live attack rows can be coerced to match (Phase 10 §9.9).
                    _learn_schema(table_name, record)

                    batch.append(record)

                    if len(batch) >= INGEST_BATCH_SIZE:
                        kusto.ingest_json(table_name, batch)
                        kusto.ingest_json('AllLogs', batch)
                        file_count += len(batch)
                        batch = []

                # Flush remaining
                if batch:
                    kusto.ingest_json(table_name, batch)
                    kusto.ingest_json('AllLogs', batch)
                    file_count += len(batch)

            if file_count > 0:
                print(f"[HISTORICAL] {table_name}: {file_count} records from {fname}",
                      flush=True)
                total_ingested += file_count

        except Exception as e:
            print(f"[HISTORICAL] Error loading {fname}: {e}", flush=True)

    print(f"[HISTORICAL] Done — {total_ingested} total records loaded into Kusto", flush=True)


# ============================================
# Built-in analytics rules
# ============================================

BUILTIN_RULES = [
    {
        'name': 'Suspicious IMDS Token Access',
        'description': 'Detect unusual access to IMDS token endpoint',
        'query': 'AllLogs | where operationName contains "IMDSAccess" and properties.endpoint contains "token" | summarize count() by source',
        'severity': 'High',
        'threshold': 1,
    },
    {
        'name': 'Mass Blob Enumeration',
        'description': 'Detect mass blob listing operations',
        'query': 'AllLogs | where operationName == "ListBlobs" | summarize count() by source | where count_ > 10',
        'severity': 'Medium',
        'threshold': 1,
    },
    {
        'name': 'Key Vault Secret Brute Force',
        'description': 'Multiple failed Key Vault secret access attempts',
        'query': 'AllLogs | where operationName == "KeyVault.GetSecret" and resultType == "Failure" | summarize count() by source | where count_ > 5',
        'severity': 'High',
        'threshold': 1,
    },
    {
        'name': 'Privilege Escalation via listKeys',
        'description': 'Detect storage account key enumeration',
        'query': 'AllLogs | where operationName contains "listKeys"',
        'severity': 'High',
        'threshold': 1,
    },
    {
        'name': 'Anomalous ARM API Calls',
        'description': 'Unusual Azure Resource Manager operations',
        'query': 'AllLogs | where category == "Administrative" and resultType == "Success" | summarize count() by operationName',
        'severity': 'Medium',
        'threshold': 5,
    },
    {
        'name': 'Unusual Sign-in Activity',
        'description': 'Failed sign-in attempts',
        'query': 'AllLogs | where category == "SignInLogs" and resultType == "Failure" | summarize count() by source | where count_ > 3',
        'severity': 'Medium',
        'threshold': 1,
    },
    {
        'name': 'Kubernetes Secrets Enumeration',
        'description': 'Detect listing of K8s secrets (T1613)',
        'query': 'AllLogs | where category == "KubeAuditLogs" and operationName == "list" and properties.resource == "secrets"',
        'severity': 'High',
        'threshold': 1,
    },
    {
        'name': 'SSRF to IMDS Token Theft',
        'description': 'Detect SSRF to IMDS for token theft (T1552.005)',
        'query': 'AllLogs | where source == "aks_pod" and properties.ssrf_target contains "169.254.169.254"',
        'severity': 'Critical',
        'threshold': 1,
    },
    {
        'name': 'Exchange Mailbox Access by Application',
        'description': 'Application accessing Exchange via Graph API (T1114.002)',
        'query': 'AllLogs | where category == "OfficeActivity" and operationName contains "MailItemsAccessed"',
        'severity': 'High',
        'threshold': 1,
    },
    {
        'name': 'Kubernetes API Reconnaissance',
        'description': 'Enumeration of K8s resources',
        'query': 'AllLogs | where category == "KubeAuditLogs" and operationName == "list" | summarize count() by properties.resource | where count_ > 2',
        'severity': 'Medium',
        'threshold': 1,
    },
    {
        'name': 'Client Credentials Grant for Graph API',
        'description': 'Detect client_credentials OAuth flow for Graph tokens',
        'query': 'AllLogs | where category == "SignInLogs" and properties.grant_type == "client_credentials" and properties.scope contains "graph.microsoft.com"',
        'severity': 'High',
        'threshold': 1,
    },
]


def initialize_builtin_rules():
    """Load built-in analytics rules."""
    with RULES_LOCK:
        for rule in BUILTIN_RULES:
            entry = dict(rule)
            entry['id'] = str(uuid.uuid4())
            entry['created'] = datetime.utcnow().isoformat() + 'Z'
            entry['builtin'] = True
            entry['enabled'] = True
            ANALYTICS_RULES.append(entry)
    print(f"[INIT] Initialized {len(BUILTIN_RULES)} built-in analytics rules", flush=True)


# ============================================
# Background threads
# ============================================

def start_collector(kusto, services):
    """Start the log collection polling thread.

    Args:
        kusto: KustoClient instance for ingestion.
        services: Dict of {service_name: service_url} to poll.
    """
    def _poll():
        print("[SENTINEL] Starting log collection thread", flush=True)
        while True:
            batch = []
            for service_name, service_url in services.items():
                try:
                    resp = requests.get(
                        f"{service_url}/audit/logs",
                        timeout=5,
                        verify=False,
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        new_logs = data if isinstance(data, list) else data.get('value', [])
                        for log in new_logs:
                            log['_source'] = service_name
                            log['source'] = service_name
                            if 'time' not in log and 'timestamp' in log:
                                log['time'] = log['timestamp']
                            # Deduplicate: skip logs we've already collected
                            fp = _log_fingerprint(log)
                            with _SEEN_IDS_LOCK:
                                if fp in _SEEN_IDS:
                                    continue
                                _SEEN_IDS.add(fp)
                                if len(_SEEN_IDS) > _MAX_SEEN_IDS:
                                    # Evict oldest ~25% (set is unordered, so just trim)
                                    to_remove = len(_SEEN_IDS) - _MAX_SEEN_IDS
                                    for _ in range(to_remove):
                                        _SEEN_IDS.pop()
                            log['collectedAt'] = datetime.utcnow().isoformat() + 'Z'
                            batch.append(log)
                except Exception as e:
                    pass  # Service may not be running

            # Buffer raw logs
            if batch:
                with RAW_LOGS_LOCK:
                    RAW_LOGS.extend(batch)
                    if len(RAW_LOGS) > MAX_RAW_LOGS:
                        RAW_LOGS[:] = RAW_LOGS[-MAX_RAW_LOGS:]

            # Ingest into Kusto
            if batch:
                categorized = {}
                for log in batch:
                    src = log.get('source') or log.get('_source') or ''
                    # Alerts: one mock alert → SecurityAlert + AlertInfo +
                    # AlertEvidence rows, each coerced to its real schema.
                    if src in _ALERT_SOURCES or 'alertId' in log:
                        for tbl, row in _expand_alert(log):
                            categorized.setdefault(tbl, []).append(
                                coerce_to_schema(row, tbl))
                        continue
                    table = get_table_for_log(log)
                    row = log
                    if table == 'SecurityEvent':
                        row = _flatten_security_event(row)
                    # Coerce attack rows to the table's real column schema (no-op
                    # for AllLogs / unknown tables). Benign rows already match.
                    # Dual-write to the real-table alias (Phase 10.2): a row
                    # routed to a fabricated mock table is ALSO written to its
                    # real Sentinel/Defender table so both names stay queryable
                    # during the migration. Coerce per target — each table owns
                    # its learned schema.
                    for tgt in (table, TABLE_ALIASES.get(table)):
                        if not tgt:
                            continue
                        categorized.setdefault(tgt, []).append(
                            coerce_to_schema(dict(row), tgt))
                for table_name, logs in categorized.items():
                    try:
                        kusto.ingest_json(table_name, logs)
                        print(f"[SENTINEL] Ingested {len(logs)} logs into {table_name}", flush=True)
                    except Exception as e:
                        print(f"[SENTINEL] Error ingesting into {table_name}: {e}", flush=True)
                    # Defender XDR dual-emit: reshape these Sentinel rows into the
                    # AH tables too (Phase 10 §3b-F). Carries the AttackTechnique
                    # tag so captured AH rows stay attack-tagged.
                    _dual_emit_xdr(kusto, table_name, logs)
                # AllLogs gets the RAW batch (preserve original fields for the
                # legacy AllLogs-querying analytics rules).
                try:
                    kusto.ingest_json('AllLogs', batch)
                except Exception:
                    pass

            time.sleep(5)

    t = Thread(target=_poll, daemon=True)
    t.start()
    return t


def start_analytics_evaluator(kusto):
    """Start the analytics rule evaluation thread."""
    def _evaluate():
        print("[ANALYTICS] Starting analytics rule evaluation thread", flush=True)
        while True:
            time.sleep(30)
            with RULES_LOCK:
                rules = [r for r in ANALYTICS_RULES if r.get('enabled', True)]
            for rule in rules:
                try:
                    result = kusto.execute_query(rule.get('query', ''))
                    tables = result.get('Tables', [])
                    if tables:
                        rows = tables[0].get('Rows', [])
                        columns = tables[0].get('Columns', [])
                        results = [
                            {columns[i]['ColumnName']: row[i] for i in range(len(columns))}
                            for row in rows
                        ]
                        if results and len(results) >= rule.get('threshold', 1):
                            _create_incident(rule, results)
                except Exception as e:
                    print(f"[ANALYTICS] Error evaluating rule {rule.get('name')}: {e}", flush=True)

    t = Thread(target=_evaluate, daemon=True)
    t.start()
    return t


def _create_incident(rule, evidence):
    """Create an incident from an analytics rule match."""
    incident = {
        'id': str(uuid.uuid4()),
        'title': rule.get('name', 'Untitled Incident'),
        'description': rule.get('description', ''),
        'severity': rule.get('severity', 'Medium'),
        'status': 'New',
        'createdTime': datetime.utcnow().isoformat() + 'Z',
        'ruleId': rule.get('id'),
        'evidenceCount': len(evidence),
        'evidence': evidence[:50],
    }
    with INCIDENTS_LOCK:
        recent = datetime.utcnow() - timedelta(minutes=5)
        existing = [
            i for i in INCIDENTS
            if i.get('ruleId') == rule.get('id')
            and datetime.fromisoformat(i['createdTime'].rstrip('Z')) > recent
        ]
        if not existing:
            INCIDENTS.append(incident)
            print(f"[INCIDENTS] Created: {incident['title']} ({incident['severity']})", flush=True)
