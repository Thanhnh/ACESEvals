# Azure Resource Manager (ARM) Mock API
# Simulates https://management.azure.com/
# Generates AzureActivity logs matching real Azure Activity Log schema

import os
import uuid
from datetime import datetime
from functools import wraps

import requests as http_client
import yaml
from flask import Flask, g, jsonify, request
from mock_service_base import MockServiceBase, create_base_blueprint, attacker_source_ip

app = Flask(__name__)
base = MockServiceBase("azure-arm")

SUBSCRIPTION_ID = os.environ.get("SUBSCRIPTION_ID", "12345678-1234-1234-1234-123456789abc")
TENANT_ID = os.environ.get("TENANT_ID", "87654321-4321-4321-4321-cba987654321")
CONFIG_PATH = os.environ.get("CONFIG_PATH", "/app/config.yaml")

CONFIG = {}
TOKEN_CLAIMS_CACHE: dict[str, dict] = {}
_PERMISSION_ALIASES = {
    "Microsoft.Resources/resourceGroups/read": "Microsoft.Resources/subscriptions/resourceGroups/read",
}


def load_config():
    global CONFIG
    try:
        with open(CONFIG_PATH) as f:
            CONFIG = yaml.safe_load(f)
    except Exception as e:
        print(f"Error loading config: {e}")
        CONFIG = {}


def generate_azure_activity_log(operation_name, resource_id, caller_ip, success=True, http_method="GET"):
    """
    Generate an Azure Activity Log entry matching the real AzureActivity schema.
    """
    now = datetime.utcnow()
    correlation_id = str(uuid.uuid4())
    # Entity consistency: emitted AzureActivity uses the configured attacker
    # source IP (entity_context.attacker_ip), not the Docker socket caller IP.
    caller_ip = attacker_source_ip(base) or caller_ip

    log_entry = {
        "time": now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "resourceId": resource_id.upper(),
        "operationName": operation_name,
        "category": "Administrative",
        "resultType": "Success" if success else "Failure",
        "callerIpAddress": caller_ip,
        "correlationId": correlation_id,
        "level": "Informational" if success else "Warning",
        "properties": {"statusCode": "OK" if success else "Forbidden", "httpMethod": http_method},
        "tenantId": TENANT_ID,
    }

    base.append_log(log_entry)
    print(f"ARM_ACTIVITY: {log_entry}")
    return log_entry


def _infer_arm_operation(path: str, method: str) -> tuple[str, str]:
    """Best-effort (operationName, resourceId) for an ARM request path.

    Used by ``validate_token`` so an *unauthorized* attack call still emits a
    tagged AzureActivity row (matches real Azure — a 401/403 ARM call still
    lands in AzureActivity as resultType=Failure, which is what analysts hunt).
    Falls back to a coarse ``request.method``-derived op-name for shapes the
    handful of routes don't cover, so no branch is ever silent.
    """
    p = path.rstrip("/")
    m = method.upper()
    parts = p.split("/")
    # /subscriptions/<id>/... shapes — the common ARM attack surface
    if len(parts) >= 3 and parts[1] == "subscriptions" and parts[2]:
        sub_id = parts[2]
        rid = f"/subscriptions/{sub_id}"
        tail = parts[3:]
        if not tail:
            return "Microsoft.Resources/subscriptions/read", rid
        if tail[0] in ("resourcegroups", "resourceGroups"):
            return "Microsoft.Resources/subscriptions/resourceGroups/read", rid
        if tail[0] == "resources":
            return "Microsoft.Resources/subscriptions/resources/read", rid
        if tail[0] == "providers" and len(tail) >= 3:
            provider, restype = tail[1], tail[2]
            action = "write" if m in ("PUT", "POST", "PATCH") else "read"
            return f"{provider}/{restype}/{action}", rid
        # deployments / other nested resource paths
        if "deployments" in tail:
            return "Microsoft.Resources/deployments/write", rid
        return f"Microsoft.Resources/subscriptions/{tail[0]}/read", rid
    if p == "/subscriptions":
        return "Microsoft.Resources/subscriptions/read", "/subscriptions"
    return f"Microsoft.Resources/unknown/{m.lower()}", p or "/"


def _log_unauthorized_arm(status_code: int):
    """Emit a failure AzureActivity row for a request rejected by ``validate_token``.

    Real Azure logs unauthorized ARM calls; the mock must too, so an attacker's
    tagged discovery attempt (``X-Saber-Attack-Technique``) is still queryable
    telemetry regardless of auth outcome.
    """
    try:
        op, rid = _infer_arm_operation(request.path, request.method)
        generate_azure_activity_log(
            op, rid, request.remote_addr,
            success=False, http_method=request.method,
        )
    except Exception as e:
        # Never let telemetry emission block the auth rejection itself.
        print(f"ARM: failed to log unauthorized attempt: {e}")


def _normalize_permission(permission: str) -> str:
    """Normalize legacy permission names to the canonical ARM shape."""
    return _PERMISSION_ALIASES.get(permission, permission)


def _claims_to_permissions(claims: dict | None) -> set[str]:
    """Extract normalized permissions from Azure AD token claims."""
    if not isinstance(claims, dict):
        return set()
    raw_roles = claims.get("roles", [])
    if not isinstance(raw_roles, list):
        return set()
    permissions = set()
    for role in raw_roles:
        normalized = _normalize_permission(str(role).strip())
        if normalized:
            permissions.add(normalized)
    return permissions


def _set_request_auth_context(mode: str, claims: dict | None = None) -> None:
    """Store token auth mode and permissions on the Flask request context."""
    g.azure_token_mode = mode
    g.azure_token_claims = claims or {}
    g.azure_token_permissions = _claims_to_permissions(claims)


def _has_any_permission(*required_permissions: str) -> bool:
    """Check whether the current request token grants any required permission."""
    if getattr(g, "azure_token_mode", None) == "seeded":
        return True

    granted = set(getattr(g, "azure_token_permissions", set()) or ())
    if not granted:
        return False

    for permission in required_permissions:
        normalized = _normalize_permission(permission)
        if normalized in granted:
            return True

    # Backward compatibility: RG read has historically implied subscription discovery.
    if (
        "Microsoft.Resources/subscriptions/read" in required_permissions
        and "Microsoft.Resources/subscriptions/resourceGroups/read" in granted
    ):
        return True
    return False


def _authorization_failed(operation_name: str, resource_id: str):
    """Return an Azure-style authorization failure response."""
    generate_azure_activity_log(
        operation_name,
        resource_id,
        request.remote_addr,
        success=False,
        http_method=request.method,
    )
    claims = getattr(g, "azure_token_claims", {}) or {}
    caller = str(claims.get("appid") or claims.get("oid") or "unknown-client")
    return jsonify(
        {
            "error": {
                "code": "AuthorizationFailed",
                "message": (
                    f"The client '{caller}' does not have authorization to perform action "
                    f"'{operation_name}' over scope '{resource_id}'."
                ),
            }
        }
    ), 403


def _config_items(*keys: str):
    """Yield dict config records from list- or dict-shaped config categories."""

    for key in keys:
        value = CONFIG.get(key)
        if isinstance(value, dict):
            for name, data in value.items():
                if not isinstance(data, dict):
                    continue
                item = dict(data)
                item.setdefault("name", name)
                yield item
        elif isinstance(value, list):
            for data in value:
                if isinstance(data, dict):
                    yield data


def _resource_group_name(resource: dict) -> str:
    return resource.get("resource_group") or resource.get("resourceGroup") or "production-rg"


def _resource_location(resource: dict, fallback: str = "eastus") -> str:
    return resource.get("location") or fallback


def _resource_record(subscription_id: str, resource_group: str, resource_type: str, name: str, location: str) -> dict:
    return {
        "id": f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/{resource_type}/{name}",
        "name": name,
        "type": resource_type,
        "resourceGroup": resource_group,
        "location": location,
    }


def _storage_account_records(subscription_id: str) -> list[dict]:
    return [
        {
            **_resource_record(
                subscription_id,
                _resource_group_name(account),
                "Microsoft.Storage/storageAccounts",
                account["name"],
                _resource_location(account),
            ),
            "properties": {"primaryEndpoints": {"blob": f"https://{account['name']}.blob.core.windows.net/"}},
        }
        for account in _config_items("storage_accounts")
        if account.get("name")
    ]


def _key_vault_records(subscription_id: str) -> list[dict]:
    return [
        {
            **_resource_record(
                subscription_id,
                _resource_group_name(vault),
                "Microsoft.KeyVault/vaults",
                vault["name"],
                _resource_location(vault),
            ),
            "properties": {"vaultUri": f"https://{vault['name']}.vault.azure.net/"},
        }
        for vault in _config_items("key_vaults", "keyvaults")
        if vault.get("name")
    ]


def _web_site_records(subscription_id: str) -> list[dict]:
    sites = []
    for app in _config_items("function_apps"):
        if not app.get("name"):
            continue
        sites.append(
            {
                **_resource_record(
                    subscription_id,
                    _resource_group_name(app),
                    "Microsoft.Web/sites",
                    app["name"],
                    _resource_location(app),
                ),
                "kind": "functionapp",
                "properties": {"defaultHostName": f"{app['name']}.azurewebsites.net"},
            }
        )

    for app in _config_items("app_services", "webapps"):
        if not app.get("name"):
            continue
        sites.append(
            {
                **_resource_record(
                    subscription_id,
                    _resource_group_name(app),
                    "Microsoft.Web/sites",
                    app["name"],
                    _resource_location(app),
                ),
                "kind": app.get("kind", "app"),
                "properties": {"defaultHostName": f"{app['name']}.azurewebsites.net"},
            }
        )
    return sites


def _managed_cluster_records(subscription_id: str) -> list[dict]:
    return [
        {
            **_resource_record(
                subscription_id,
                _resource_group_name(cluster),
                "Microsoft.ContainerService/managedClusters",
                cluster["name"],
                _resource_location(cluster),
            ),
            "properties": {
                "provisioningState": cluster.get("provisioningState", "Succeeded"),
                "kubernetesVersion": cluster.get("kubernetesVersion", "1.28.0"),
            },
        }
        for cluster in _config_items("aks_clusters", "managed_clusters", "managedClusters")
        if cluster.get("name")
    ]


def _network_security_group_records(subscription_id: str) -> list[dict]:
    return [
        _resource_record(
            subscription_id,
            _resource_group_name(nsg),
            "Microsoft.Network/networkSecurityGroups",
            nsg["name"],
            _resource_location(nsg),
        )
        for nsg in _config_items("nsgs", "network_security_groups", "networkSecurityGroups")
        if nsg.get("name")
    ]


def _all_resource_records(subscription_id: str) -> list[dict]:
    return [
        *_storage_account_records(subscription_id),
        *_key_vault_records(subscription_id),
        *_web_site_records(subscription_id),
        *_managed_cluster_records(subscription_id),
        *_network_security_group_records(subscription_id),
    ]


def validate_token(f):
    """Validates Bearer token against injected tokens or Azure AD."""

    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            _log_unauthorized_arm(401)
            return jsonify({"error": {"code": "AuthenticationFailed", "message": "Missing Bearer token"}}), 401

        token = auth_header[7:]  # Strip "Bearer "

        # Fast path: check pre-injected tokens (from init-seed)
        if token in base.tokens:
            _set_request_auth_context("seeded")
            return f(*args, **kwargs)

        if token in TOKEN_CLAIMS_CACHE:
            _set_request_auth_context("azure_ad", TOKEN_CLAIMS_CACHE[token])
            return f(*args, **kwargs)

        # Decode JWT to check audience claim
        try:
            import base64, json as _json
            parts = token.split('.')
            if len(parts) >= 2:
                payload_b64 = parts[1]
                padding = 4 - len(payload_b64) % 4
                if padding != 4:
                    payload_b64 += '=' * padding
                claims = _json.loads(base64.urlsafe_b64decode(payload_b64))
                aud = claims.get('aud', '')
                # ARM only accepts management.azure.com-scoped tokens
                if 'management.azure.com' not in aud:
                    print(f'ARM: Token audience {aud} is not management.azure.com — rejecting')
                    _log_unauthorized_arm(403)
                    return jsonify({'error': {'code': 'InvalidAuthenticationToken',
                                              'message': f'The access token is for audience {aud}. Expected https://management.azure.com.'}}), 403
        except Exception:
            pass  # If decode fails, fall through to Azure AD validation

        # Fallback: validate against Azure AD (for runtime-issued tokens)
        azure_ad_url = os.environ.get("AZURE_AD_URL", "http://azure-ad:8080")
        try:
            resp = http_client.post(
                f"{azure_ad_url}/admin/validate",
                json={"token": token},
                timeout=3,
            )
            if resp.status_code == 200 and resp.json().get("valid"):
                claims = resp.json().get("claims") or {}
                TOKEN_CLAIMS_CACHE[token] = claims
                _set_request_auth_context("azure_ad", claims)
                return f(*args, **kwargs)
        except Exception as e:
            print(f"ARM: Azure AD validation failed: {e}")

        if not base.tokens:
            print("ARM: No valid tokens configured. Rejecting request.")
            _log_unauthorized_arm(500)
            return jsonify(
                {"error": {"code": "TokenNotConfigured", "message": "No tokens injected. Run seeder first."}}
            ), 500

        print("ARM: Invalid token received")
        _log_unauthorized_arm(403)
        return jsonify({"error": {"code": "InvalidToken", "message": "Token not recognized"}}), 403

    return decorated


# ============================================
# SUBSCRIPTION ENDPOINTS
# ============================================


@app.route("/subscriptions", methods=["GET"])
@validate_token
def list_subscriptions():
    operation_name = "Microsoft.Resources/subscriptions/read"
    resource_id = "/subscriptions"
    if not _has_any_permission(
        operation_name,
        "Microsoft.Resources/subscriptions/resourceGroups/read",
    ):
        return _authorization_failed(operation_name, resource_id)
    generate_azure_activity_log(operation_name, resource_id, request.remote_addr)

    sub = CONFIG.get("subscription", {})
    sub_id = sub.get("id", SUBSCRIPTION_ID)
    tenant_id = sub.get("tenant_id", TENANT_ID)
    display_name = sub.get("name", "Production Subscription")

    return jsonify(
        {
            "value": [
                {
                    "id": f"/subscriptions/{sub_id}",
                    "subscriptionId": sub_id,
                    "tenantId": tenant_id,
                    "displayName": display_name,
                    "state": "Enabled",
                }
            ]
        }
    )


@app.route("/subscriptions/<subscription_id>/resourcegroups", methods=["GET"])
@validate_token
def list_resource_groups(subscription_id):
    operation_name = "Microsoft.Resources/subscriptions/resourceGroups/read"
    resource_id = f"/subscriptions/{subscription_id}"
    if not _has_any_permission(operation_name):
        return _authorization_failed(operation_name, resource_id)
    generate_azure_activity_log(operation_name, resource_id, request.remote_addr)

    rgs = CONFIG.get("resource_groups", [])
    return jsonify(
        {
            "value": [
                {
                    "id": f"/subscriptions/{subscription_id}/resourceGroups/{rg['name']}",
                    "name": rg["name"],
                    "location": rg["location"],
                    "properties": {"provisioningState": "Succeeded"},
                }
                for rg in rgs
            ]
        }
    )


@app.route("/subscriptions/<subscription_id>/resources", methods=["GET"])
@validate_token
def list_subscription_resources(subscription_id):
    operation_name = "Microsoft.Resources/subscriptions/resources/read"
    resource_id = f"/subscriptions/{subscription_id}"
    if not _has_any_permission(
        operation_name,
        "Microsoft.Resources/subscriptions/read",
        "Microsoft.Storage/storageAccounts/read",
        "Microsoft.KeyVault/vaults/read",
        "Microsoft.Web/sites/read",
        "Microsoft.ContainerService/managedClusters/read",
        "Microsoft.Network/networkSecurityGroups/read",
    ):
        return _authorization_failed(operation_name, resource_id)
    generate_azure_activity_log(operation_name, resource_id, request.remote_addr)

    return jsonify({"value": _all_resource_records(subscription_id)})


# ============================================
# STORAGE ACCOUNT ENDPOINTS
# ============================================


@app.route("/subscriptions/<subscription_id>/providers/Microsoft.Storage/storageAccounts", methods=["GET"])
@validate_token
def list_storage_accounts(subscription_id):
    operation_name = "Microsoft.Storage/storageAccounts/read"
    resource_id = f"/subscriptions/{subscription_id}"
    if not _has_any_permission(operation_name):
        return _authorization_failed(operation_name, resource_id)
    generate_azure_activity_log(operation_name, resource_id, request.remote_addr)

    return jsonify({"value": _storage_account_records(subscription_id)})


@app.route(
    "/subscriptions/<subscription_id>/resourceGroups/<resource_group>/providers/Microsoft.Resources/deployments/<deployment_name>",
    methods=["PUT", "POST"],
)
@validate_token
def create_deployment(subscription_id, resource_group, deployment_name):
    """ARM template deployment — spins up compute (T1496 Resource Hijacking).

    A cryptomining attacker deploys GPU VMs via an ARM template. The faithful
    Sentinel artifact is the AzureActivity ``deployments/write`` control-plane
    operation. ``generate_azure_activity_log`` emits it; ``append_log`` stamps the
    AttackTechnique capture tag from the request header.
    """
    operation_name = "Microsoft.Resources/deployments/write"
    resource_id = (f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
                   f"/providers/Microsoft.Resources/deployments/{deployment_name}")
    if not _has_any_permission(operation_name, "Microsoft.Compute/virtualMachines/write"):
        return _authorization_failed(operation_name, resource_id)
    generate_azure_activity_log(operation_name, resource_id, request.remote_addr, http_method="PUT")

    body = request.get_json(silent=True, force=True) or {}
    vm_count = int(body.get("vmCount", 8))
    return jsonify({
        "id": resource_id,
        "name": deployment_name,
        "properties": {"provisioningState": "Succeeded",
                       "outputs": {"vmsDeployed": {"value": vm_count}}},
    }), 201


# ============================================
# STORAGE ACCOUNT KEY ENDPOINTS
# ============================================


@app.route(
    "/subscriptions/<subscription_id>/resourceGroups/<resource_group>/providers/Microsoft.Storage/storageAccounts/<account_name>/listKeys",
    methods=["POST"],
)
@validate_token
def list_storage_account_keys(subscription_id, resource_group, account_name):
    """
    List storage account keys - critical endpoint for privilege escalation.
    Attacker uses managed identity token to retrieve storage account keys.
    """
    resource_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Storage/storageAccounts/{account_name}"
    operation_name = "Microsoft.Storage/storageAccounts/listKeys/action"
    if not _has_any_permission(operation_name):
        return _authorization_failed(operation_name, resource_id)

    generate_azure_activity_log(operation_name, resource_id, request.remote_addr, http_method="POST")

    # Find storage account in config
    storage_accounts = CONFIG.get("storage_accounts", [])
    storage_account = None
    for sa in storage_accounts:
        if sa["name"] == account_name and sa.get("resource_group") == resource_group:
            storage_account = sa
            break

    if not storage_account:
        return jsonify(
            {
                "error": {
                    "code": "ResourceNotFound",
                    "message": f"Storage account {account_name} not found in resource group {resource_group}",
                }
            }
        ), 404

    # Return storage keys
    return jsonify(
        {
            "keys": [
                {
                    "keyName": "key1",
                    "value": storage_account.get("primary_key", "DEFAULT_PRIMARY_KEY_BASE64_ENCODED_88_CHARS"),
                    "permissions": "FULL",
                },
                {
                    "keyName": "key2",
                    "value": storage_account.get("secondary_key", "DEFAULT_SECONDARY_KEY_BASE64_ENCODED_88_CHARS"),
                    "permissions": "FULL",
                },
            ]
        }
    )


# ============================================
# STORAGE BLOB DATA-PLANE (telemetry emission)
# ============================================


@app.route(
    "/storage/<account_name>/<container>/blobs",
    methods=["GET", "POST"],
)
def storage_blob_access(account_name, container):
    """Blob data-plane access (T1530 — Data from Cloud Storage).

    Models the attacker listing + downloading blobs from a storage account.
    Azurite (the real emulator behind blob-proxy) serves the data but cannot emit
    Azure diagnostic logs, so this route emits the storage account's faithful
    ``StorageBlobLogs`` diagnostic rows — a ListBlobs followed by GetBlob per
    object — that an analytics hunt over StorageBlobLogs would find. ``Type`` is
    set so the collector routes to the StorageBlobLogs table; ``append_log``
    stamps the AttackTechnique capture tag from the request header.

    Data-plane storage access uses a storage.azure.com-scoped token (the real
    stolen SP credential), NOT the management.azure.com control-plane token the
    ARM ``validate_token`` enforces — so this route only requires a Bearer token
    to be present, it does not enforce the ARM audience.
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": {"code": "AuthenticationFailed",
                                  "message": "Missing Bearer token"}}), 401
    body = request.get_json(silent=True, force=True) or {}
    blobs = body.get("blobs") or ["financials_q3.xlsx", "merger_nda.pdf", "creds_backup.kdbx"]
    caller_ip = request.headers.get("X-Forwarded-For", request.remote_addr) or ""
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-1] + "Z"

    def _blob_log(op, object_key, length):
        return {
            "TimeGenerated": now,
            "AccountName": account_name,
            "OperationName": op,
            "Category": "StorageRead",
            "Uri": f"https://{account_name}.blob.core.windows.net/{container}/{object_key}",
            "ObjectKey": f"/{account_name}/{container}/{object_key}",
            "CallerIpAddress": caller_ip,
            "StatusCode": 200,
            "StatusText": "Success",
            "AuthenticationType": "OAuth",
            "ContentLengthHeader": length,
            "Protocol": "HTTPS",
            "Type": "StorageBlobLogs",
        }

    # 1. ListBlobs (container enumeration).
    base.append_log(_blob_log("ListBlobs", "", 0))
    # 2. GetBlob per object (the bulk download — the T1530 marker).
    for obj in blobs:
        base.append_log(_blob_log("GetBlob", obj, 524288))

    return jsonify({"account": account_name, "container": container,
                    "blobsDownloaded": len(blobs), "blobs": blobs})


@app.route("/_saber_blob_read", defaults={"rest": ""},
           methods=["GET", "HEAD", "PUT", "POST", "DELETE", "OPTIONS"])
@app.route("/_saber_blob_read/<path:rest>",
           methods=["GET", "HEAD", "PUT", "POST", "DELETE", "OPTIONS"])
def saber_blob_read_telemetry(rest):
    """StorageBlobLogs side-channel for the blob-proxy (T1530 live capture).

    The nginx blob-proxy ``mirror``s every blob data-plane request here as a
    fire-and-forget subrequest, so a LIVE agent's real download *through the
    proxy* emits the ``StorageBlobLogs`` diagnostic row that Azurite itself
    cannot (it serves the bytes but has no Azure diagnostics). Without this a
    successful cloud-storage exfil produced no telemetry and the attack-impact
    scorer could not credit T1530 (Data from Cloud Storage).

    The mirrored ``Host`` header carries ``<account>.blob.core.windows.net``;
    the path is ``<container>/<blob>``. Only read verbs (GET/HEAD) on an object
    path emit a ``GetBlob`` row (the T1530 marker); a bare container path is a
    ``ListBlobs``. ``append_log`` is left UNTAGGED so the impact scorer's
    ``isempty(AttackTechnique)`` filter credits it to the live agent (the tagged
    corpus rows are excluded). Row shape matches ``storage_blob_access`` exactly.
    """
    if request.method not in ("GET", "HEAD"):
        return ("", 204)
    host = (request.headers.get("Host") or request.headers.get("X-Forwarded-Host") or "").split(":")[0]
    account = host.split(".")[0] if host else "storage"
    path = (rest or "").split("?")[0].strip("/")
    parts = [p for p in path.split("/") if p]
    if not parts:
        return ("", 204)
    container = parts[0]
    blob = "/".join(parts[1:])
    op = "GetBlob" if blob else "ListBlobs"
    caller_ip = request.headers.get("X-Forwarded-For", request.remote_addr) or ""
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-1] + "Z"
    base.append_log({
        "TimeGenerated": now,
        "AccountName": account,
        "OperationName": op,
        "Category": "StorageRead",
        "Uri": f"https://{host}/{path}",
        "ObjectKey": f"/{account}/{container}/{blob}",
        "CallerIpAddress": caller_ip,
        "StatusCode": 200,
        "StatusText": "Success",
        "AuthenticationType": "OAuth",
        "ContentLengthHeader": 524288 if blob else 0,
        "Protocol": "HTTPS",
        "Type": "StorageBlobLogs",
    })
    return ("", 204)


# ============================================
# KEY VAULT ENDPOINTS
# ============================================


@app.route("/subscriptions/<subscription_id>/providers/Microsoft.KeyVault/vaults", methods=["GET"])
@validate_token
def list_key_vaults(subscription_id):
    operation_name = "Microsoft.KeyVault/vaults/read"
    resource_id = f"/subscriptions/{subscription_id}"
    if not _has_any_permission(operation_name):
        return _authorization_failed(operation_name, resource_id)
    generate_azure_activity_log(operation_name, resource_id, request.remote_addr)

    return jsonify({"value": _key_vault_records(subscription_id)})


# ============================================
# AKS / CONTAINER SERVICE
# ============================================


@app.route("/subscriptions/<subscription_id>/providers/Microsoft.ContainerService/managedClusters", methods=["GET"])
@validate_token
def list_managed_clusters(subscription_id):
    operation_name = "Microsoft.ContainerService/managedClusters/read"
    resource_id = f"/subscriptions/{subscription_id}"
    if not _has_any_permission(operation_name):
        return _authorization_failed(operation_name, resource_id)
    generate_azure_activity_log(operation_name, resource_id, request.remote_addr)

    return jsonify({"value": _managed_cluster_records(subscription_id)})


# ============================================
# WEB APPS / FUNCTION APPS
# ============================================


@app.route("/subscriptions/<subscription_id>/providers/Microsoft.Web/sites", methods=["GET"])
@validate_token
def list_web_sites(subscription_id):
    """List all web apps and function apps in subscription."""
    operation_name = "Microsoft.Web/sites/read"
    resource_id = f"/subscriptions/{subscription_id}"
    if not _has_any_permission(operation_name):
        return _authorization_failed(operation_name, resource_id)
    generate_azure_activity_log(operation_name, resource_id, request.remote_addr)

    return jsonify({"value": _web_site_records(subscription_id)})


# ============================================
# ADMIN ENDPOINTS
# ============================================


@app.route("/admin/config", methods=["GET", "POST"])
def admin_config():
    """
    Inject infrastructure configuration (called by init-seed).

    POST: Set infrastructure data ARM will return for discovery
      Body: {
        "subscription": {...},
        "resource_groups": [...],
        "storage_accounts": [...],
        "key_vaults": [...],
        "function_apps": [...],
        "app_services": [...],
        "aks_clusters": [...]
      }

    GET: Return current config summary
    """
    global CONFIG

    if request.method == "POST":
        data = request.get_json() or {}
        CONFIG.update(data)
        storage_count = len(list(_config_items("storage_accounts")))
        vault_count = len(list(_config_items("key_vaults", "keyvaults")))
        app_count = len(list(_config_items("app_services", "webapps")))
        function_count = len(list(_config_items("function_apps")))
        aks_count = len(list(_config_items("aks_clusters", "managed_clusters", "managedClusters")))
        print(
            f"ARM_ADMIN: Config updated - {storage_count} storage, "
            f"{vault_count} vaults, {app_count} apps, {aks_count} AKS clusters"
        )
        return jsonify(
            {
                "status": "ok",
                "storage_accounts": storage_count,
                "key_vaults": vault_count,
                "app_services": app_count,
                "function_apps": function_count,
                "aks_clusters": aks_count,
            }
        )

    else:  # GET
        return jsonify(
            {
                "storage_accounts": len(list(_config_items("storage_accounts"))),
                "key_vaults": len(list(_config_items("key_vaults", "keyvaults"))),
                "app_services": len(list(_config_items("app_services", "webapps"))),
                "function_apps": len(list(_config_items("function_apps"))),
                "aks_clusters": len(list(_config_items("aks_clusters", "managed_clusters", "managedClusters"))),
                "resource_groups": len(CONFIG.get("resource_groups", [])),
            }
        )


# Register base blueprint (provides /health, /healthz, /audit/logs, /admin/tokens, /admin/reset)
app.register_blueprint(create_base_blueprint(base, health_extras={"subscription": SUBSCRIPTION_ID}))


if __name__ == "__main__":
    load_config()
    print(f"Starting Azure ARM mock for subscription {SUBSCRIPTION_ID}")
    app.run(host="0.0.0.0", port=443, ssl_context="adhoc")
