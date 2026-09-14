"""Standalone seeding script for init container.

Seeds mock Azure services from seed_manifest.template.yaml.
Generates random values for placeholders at startup time.

No secrets in git - everything is generated fresh each deployment.
"""

import base64
import hashlib
import hmac
import json
import os
import random
import re
import secrets
import string
import time
import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

import requests
import yaml
from azure.storage.blob import AccountSasPermissions, ResourceTypes, generate_account_sas

# =============================================================================
# Constants
# =============================================================================

# Azurite's well-known development key - used for local Azure Storage emulation
# This is a public test key, NOT a secret. Safe to commit.
# See: https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azurite
# Split to avoid git secret scanning false positives
_AZURITE_KEY_A = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsu"
_AZURITE_KEY_B = "Fq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
AZURITE_WELL_KNOWN_KEY = _AZURITE_KEY_A + _AZURITE_KEY_B


# On-prem AD realm / NetBIOS name for credential artifacts (Kerberos TGT/TGS,
# LSASS dumps). Threaded in from the range's intent.yaml via the AD_REALM /
# AD_NETBIOS env vars (set by deterministic_assembly from
# entity_context.on_prem_domain). Falls back to CONTOSO only when unset so a
# range never stamps a different fictional org's on-prem artifacts as CONTOSO —
# a realness tell in credential-access scenarios. (Phase 10 §7.3 / §9.3)
AD_REALM = os.getenv("AD_REALM", "CONTOSO.LOCAL").upper()
AD_NETBIOS = os.getenv("AD_NETBIOS") or AD_REALM.split(".")[0]


# =============================================================================
# Value Generation
# =============================================================================


def generate_base64_key(length: int = 64) -> str:
    """Generate a base64-encoded random key (like Azure storage keys)."""
    raw_bytes = secrets.token_bytes(length)
    return base64.b64encode(raw_bytes).decode("utf-8")


def generate_uuid() -> str:
    """Generate a random UUID."""
    return str(uuid.uuid4())


def generate_uuid_secret() -> str:
    """Generate a UUID-like secret (Azure SP format)."""
    return f"{generate_uuid()}".replace("-", "")[:32] + "=="


def generate_password(length: int = 24) -> str:
    """Generate a random password."""
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(chars) for _ in range(length))


def generate_hex(length: int = 32) -> str:
    """Generate random hex string."""
    return secrets.token_hex(length // 2)


def generate_api_key(prefix: str = "", length: int = 32) -> str:
    """Generate an API key."""
    key = secrets.token_urlsafe(length)[:length]
    return f"{prefix}{key}" if prefix else key


def generate_sas_token(account_name: str = None, account_key: str = None) -> str:
    """Generate a valid SAS token using the Azure SDK.

    Uses the storage account key to compute a cryptographically valid signature
    that will be accepted by Azurite.
    """
    # Default to Azurite's well-known key if not provided
    if account_name is None:
        account_name = os.getenv("STORAGE_ACCOUNT_NAME", "proddata001")
    if account_key is None:
        account_key = os.getenv("STORAGE_ACCOUNT_KEY", AZURITE_WELL_KNOWN_KEY)

    expiry = datetime.now(UTC) + timedelta(days=365)

    sas_token = generate_account_sas(
        account_name=account_name,
        account_key=account_key,
        resource_types=ResourceTypes(service=True, container=True, object=True),
        permission=AccountSasPermissions(read=True, write=True, delete=True, list=True, add=True, create=True),
        expiry=expiry,
    )
    return sas_token


def generate_oauth_token(
    issuer: str = "https://login.microsoftonline.com/fake-tenant-id/v2.0",
    audience: str = "https://management.azure.com",
    subject: str = None,
    upn: str = None,
    object_id: str = None,
    expires_in: int = 3600,
) -> str:
    """Generate a fake but structurally valid Azure AD OAuth token (JWT).

    Creates a JWT with realistic Azure AD claims. The signature is fake
    but the structure matches what Azure AD returns for managed identity tokens.
    When ``object_id`` is supplied (the owning user's seeded directory id), it is
    used for the ``oid``/``sub`` claims so the token carries the REAL identity —
    the mocks then record that principal as the actor in emitted telemetry,
    keeping the attack consistent with the seed + benign baseline.
    """
    now = int(time.time())
    tenant_id = str(uuid.uuid4())
    object_id = object_id or str(uuid.uuid4())

    # JWT Header
    header = {"typ": "JWT", "alg": "RS256", "kid": generate_hex(20)}

    # JWT Payload with Azure AD claims
    payload = {
        "aud": audience,
        "iss": issuer,
        "iat": now,
        "nbf": now,
        "exp": now + expires_in,
        "aio": generate_hex(43),  # Azure internal claim
        "appid": str(uuid.uuid4()),
        "appidacr": "2",
        "idp": issuer,
        "oid": object_id,
        "rh": generate_hex(24),
        "sub": subject or object_id,
        "tid": tenant_id,
        "uti": generate_hex(11),
        "ver": "2.0",
        "xms_mirid": f"/subscriptions/{uuid.uuid4()}/resourcegroups/rg-prod/providers/Microsoft.Web/sites/app-service",
    }
    # Add upn claim if provided (used by Exchange /me/ resolution)
    if upn:
        payload["upn"] = upn

    # Base64url encode (no padding)
    def b64url(data: dict) -> str:
        json_bytes = json.dumps(data, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(json_bytes).rstrip(b"=").decode()

    header_b64 = b64url(header)
    payload_b64 = b64url(payload)
    # Fake signature (256 bytes like RS256)
    signature_b64 = base64.urlsafe_b64encode(secrets.token_bytes(256)).rstrip(b"=").decode()

    return f"{header_b64}.{payload_b64}.{signature_b64}"


# ---------------------------------------------------------------------------
# MDE / Windows Endpoint credential generators (Phase 1)
# ---------------------------------------------------------------------------

def generate_ntlm_hash() -> str:
    """Generate format-correct NTLM hash (LM:NT format)."""
    lm_part = "aad3b435b51404eeaad3b435b51404ee"
    nt_part = secrets.token_hex(16)
    return f"{lm_part}:{nt_part}"


def generate_kerberos_tgt(principal: str | None = None,
                          realm: str | None = None) -> str:
    """Generate mock Kerberos TGT as base64-encoded JSON."""
    realm = (realm or AD_REALM).upper()
    if principal is None:
        principal = f"user@{realm}"
    ticket = {
        "type": "TGT",
        "principal": principal,
        "realm": realm,
        "session_key": secrets.token_hex(16),
        "issued": datetime.now(UTC).isoformat(),
        "expires": (datetime.now(UTC) + timedelta(hours=10)).isoformat(),
        "flags": ["forwardable", "renewable"],
    }
    return base64.b64encode(json.dumps(ticket).encode()).decode()


def generate_lsass_dump(accounts: list[dict]) -> list[dict]:
    """Generate mock LSASS dump output — list of credential entries."""
    return [
        {
            "username": acct.get("username", "user"),
            "domain": acct.get("domain", AD_NETBIOS),
            "ntlm_hash": generate_ntlm_hash(),
            "password": acct.get("password"),
        }
        for acct in accounts
    ]


def generate_prt_token(device_id: str) -> str:
    """Generate mock Primary Refresh Token (JWT-like)."""
    header = base64.b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).decode()
    payload = base64.b64encode(json.dumps({
        "device_id": device_id,
        "session_key": secrets.token_hex(32),
        "iat": int(datetime.now(UTC).timestamp()),
        "exp": int((datetime.now(UTC) + timedelta(hours=24)).timestamp()),
    }).encode()).decode()
    sig = secrets.token_urlsafe(32)
    return f"{header}.{payload}.{sig}"


def generate_sid(rid: int | None = None) -> str:
    """Generate Windows SID format."""
    parts = [random.randint(1000000000, 4294967295) for _ in range(3)]
    rid = rid or random.randint(1000, 9999)
    return f"S-1-5-21-{parts[0]}-{parts[1]}-{parts[2]}-{rid}"


# ---------------------------------------------------------------------------
# Phase 3: ADFS credential generators
# ---------------------------------------------------------------------------

def generate_adfs_signing_key() -> str:
    """Generate mock ADFS token signing private key (PEM-encoded, not real RSA)."""
    mock_key_data = secrets.token_bytes(256)
    b64_key = base64.b64encode(mock_key_data).decode()
    lines = [b64_key[i:i+64] for i in range(0, len(b64_key), 64)]
    return "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END RSA PRIVATE KEY-----"


def generate_x509_cert() -> str:
    """Generate mock X.509 certificate (PEM-encoded, not real crypto)."""
    mock_cert_data = secrets.token_bytes(256)
    b64_cert = base64.b64encode(mock_cert_data).decode()
    lines = [b64_cert[i:i+64] for i in range(0, len(b64_cert), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----"


def generate_value(placeholder_def: dict) -> str:
    """Generate a value based on placeholder definition."""
    ptype = placeholder_def.get("type", "random_hex")

    if ptype == "static":
        # Return the static value as-is
        return placeholder_def.get("value", "")
    elif ptype == "base64":
        length = placeholder_def.get("length", 64)
        return generate_base64_key(length)
    elif ptype == "uuid":
        return generate_uuid()
    elif ptype == "uuid_secret":
        return generate_uuid_secret()
    elif ptype == "password":
        length = placeholder_def.get("length", 24)
        return generate_password(length)
    elif ptype == "random_hex":
        length = placeholder_def.get("length", 32)
        return generate_hex(length)
    elif ptype == "api_key":
        prefix = placeholder_def.get("prefix", "")
        length = placeholder_def.get("length", 32)
        return generate_api_key(prefix, length)
    elif ptype == "sas_token":
        return generate_sas_token()
    elif ptype == "oauth_token":
        # Generate Azure AD-style OAuth token (JWT)
        issuer = placeholder_def.get("issuer", "https://login.microsoftonline.com/fake-tenant-id/v2.0")
        audience = placeholder_def.get("audience", "https://management.azure.com")
        expires_in = placeholder_def.get("expires_in", 3600)
        subject = placeholder_def.get("subject")
        upn = placeholder_def.get("upn")
        object_id = placeholder_def.get("object_id")
        return generate_oauth_token(issuer=issuer, audience=audience,
                                    subject=subject, upn=upn,
                                    object_id=object_id,
                                    expires_in=expires_in)
    elif ptype == "connection_string":
        # Connection strings may have nested placeholders
        return placeholder_def.get("format", "")
    elif ptype == "ntlm_hash":
        return generate_ntlm_hash()
    elif ptype == "kerberos_tgt":
        principal = placeholder_def.get("principal", f"user@{AD_REALM}")
        realm = placeholder_def.get("realm", AD_REALM)
        return generate_kerberos_tgt(principal, realm)
    elif ptype == "kerberos_tgs":
        spn = placeholder_def.get("spn", f"MSSQLSvc/sql01.{AD_REALM.lower()}:1433")
        realm = placeholder_def.get("realm", AD_REALM)
        return generate_kerberos_tgt(spn, realm)
    elif ptype == "lsass_dump":
        accounts = placeholder_def.get("accounts", [{"username": "admin"}])
        return json.dumps(generate_lsass_dump(accounts))
    elif ptype == "prt_token":
        device_id = placeholder_def.get("device_id", str(uuid.uuid4()))
        return generate_prt_token(device_id)
    elif ptype == "sid":
        rid = placeholder_def.get("rid")
        return generate_sid(rid)
    elif ptype == "adfs_signing_key":
        return generate_adfs_signing_key()
    elif ptype == "x509_cert":
        return generate_x509_cert()
    else:
        return generate_hex(32)


# =============================================================================
# Template Processing
# =============================================================================


def load_template(path: str = "/app/seed_manifest.template.yaml") -> dict:
    """Load seed manifest template."""
    with open(path) as f:
        return yaml.safe_load(f)


def generate_all_values(template: dict) -> dict:
    """Generate values for all placeholders defined in template.

    Sources for definitions (in priority order):
    1. Explicit ``placeholder_definitions`` section (legacy format)
    2. ``credentials`` section – each entry has a ``type`` field compatible
       with ``generate_value()`` (e.g. sas_token, oauth_token).
    3. Any remaining ``{{ NAME }}`` patterns found anywhere in the template
       are generated as random hex (safe default).
    """
    values: dict[str, str] = {}
    definitions: dict[str, dict] = dict(template.get("placeholder_definitions", {}))

    # Derive definitions from credentials section when placeholder_definitions
    # is absent (common in LLM-generated templates).
    if not definitions:
        for name, cred in template.get("credentials", {}).items():
            if isinstance(cred, dict) and "type" in cred:
                definitions[name] = cred

    # Scan the entire template for {{ NAME }} patterns that aren't covered
    # by explicit definitions and generate sensible defaults for them.
    template_str = yaml.dump(template)
    for match in re.finditer(r"\{\{\s*(\w+)\s*\}\}", template_str):
        placeholder_name = match.group(1)
        if placeholder_name not in definitions:
            # Infer type from the placeholder name when possible
            if "SECRET" in placeholder_name or "PASSWORD" in placeholder_name:
                definitions[placeholder_name] = {"type": "uuid_secret"}
            elif "KEY" in placeholder_name:
                definitions[placeholder_name] = {"type": "base64", "length": 64}
            elif "TOKEN" in placeholder_name:
                definitions[placeholder_name] = {"type": "oauth_token"}
            else:
                definitions[placeholder_name] = {"type": "random_hex", "length": 32}

    # Link each oauth_token placeholder to its owning user (UPN + seeded
    # object_id) discovered from the services.*.users blocks (each user entry is
    # ``{upn: {object_id, token: "{{ TOKEN_NAME }}", ...}}``). The minted JWT
    # then carries the real identity claims, so when the attack wields the token
    # the mocks record the compromised user as the actor — matching the seed
    # manifest + benign baseline.
    for sval in (template.get("services", {}) or {}).values():
        if not isinstance(sval, dict):
            continue
        _users = sval.get("users")
        if not isinstance(_users, dict):
            continue
        for upn, info in _users.items():
            if not isinstance(info, dict):
                continue
            tok = info.get("token")
            oid = info.get("object_id")
            if isinstance(tok, str):
                m = re.search(r"\{\{\s*(\w+)\s*\}\}", tok)
                if m:
                    d = definitions.get(m.group(1))
                    if isinstance(d, dict) and d.get("type") == "oauth_token":
                        d.setdefault("upn", str(upn))
                        if oid:
                            d.setdefault("object_id", str(oid))

    # First pass: generate basic values
    for name, definition in definitions.items():
        values[name] = generate_value(definition)
    # Second pass: resolve nested references in connection strings
    for name, definition in definitions.items():
        if definition.get("type") == "connection_string":
            fmt = definition.get("format", "")
            for ref_name, ref_value in values.items():
                fmt = fmt.replace("{{ " + ref_name + " }}", ref_value)
            values[name] = fmt

    return values


def resolve_placeholders(template: dict, values: dict) -> dict:
    """Replace all {{ PLACEHOLDER }} patterns with generated values.

    Perform replacement in-memory (dict/list/str) rather than via a YAML
    dump/re-parse roundtrip. This avoids PyYAML scanner failures when resolved
    placeholder values are very long and appear in mapping keys.
    """

    def _replace_in_obj(obj):
        if isinstance(obj, str):
            out = obj
            for name, value in values.items():
                pattern = r"\{\{\s*" + re.escape(name) + r"\s*\}\}"
                out = re.sub(pattern, value, out)
            return out
        if isinstance(obj, list):
            return [_replace_in_obj(v) for v in obj]
        if isinstance(obj, dict):
            return {_replace_in_obj(k): _replace_in_obj(v) for k, v in obj.items()}
        return obj

    resolved = _replace_in_obj(template)

    # Remove placeholder_definitions from output (not needed for seeding)
    if "placeholder_definitions" in resolved:
        del resolved["placeholder_definitions"]

    return resolved


def resolve_runtime_initial_state(bundle_dir: str, values: dict) -> None:
    """Resolve ``{{ }}`` placeholders in ``az_initial_state.json`` and write a runtime copy.

    Reads ``<bundle_dir>/inputs/az_initial_state.json``, substitutes placeholders
    using *values*, and writes the resolved version to
    ``<bundle_dir>/inputs/az_initial_state.runtime.json``.  The original template
    file is left untouched.

    Env-var overrides (used by init containers):
      - ``AZ_INITIAL_STATE_TEMPLATE_PATH`` — override source path
      - ``AZ_INITIAL_STATE_OUTPUT_PATH`` — override output path
    """
    inputs_dir = os.path.join(bundle_dir, "inputs")
    template_path = os.environ.get(
        "AZ_INITIAL_STATE_TEMPLATE_PATH",
        os.path.join(inputs_dir, "az_initial_state.json"),
    )
    output_path = os.environ.get(
        "AZ_INITIAL_STATE_OUTPUT_PATH",
        os.path.join(inputs_dir, "az_initial_state.runtime.json"),
    )

    if not os.path.isfile(template_path):
        print(f"  az_initial_state.json not found at {template_path} — skipping")
        return

    with open(template_path) as f:
        raw = f.read()

    # Substitute {{ PLACEHOLDER }} patterns
    for name, value in values.items():
        pattern = r"\{\{\s*" + re.escape(name) + r"\s*\}\}"
        raw = re.sub(pattern, str(value), raw)

    with open(output_path, "w") as f:
        f.write(raw)

    print(f"  Wrote resolved initial state to: {output_path}")


def load_and_resolve_template(template_path: str = "/app/seed_manifest.template.yaml") -> dict:
    """Load template and resolve all placeholders."""
    template = load_template(template_path)
    values = generate_all_values(template)

    print("Generated values:")
    for name in values:
        # Show first 20 chars of each value
        preview = values[name][:20] + "..." if len(values[name]) > 20 else values[name]
        print(f"  {name}: {preview}")

    resolved = resolve_placeholders(template, values)

    # Write resolved manifest to output if directory is mounted
    output_path = os.getenv("RESOLVED_MANIFEST_PATH", "/app/output/seed_manifest.yaml")
    output_dir = os.path.dirname(output_path)
    if os.path.exists(output_dir) and os.path.isdir(output_dir):
        try:
            with open(output_path, "w") as f:
                yaml.dump(resolved, f, default_flow_style=False, sort_keys=False)
            print(f"  Wrote resolved manifest to: {output_path}")
        except Exception as e:
            print(f"  WARNING: Could not write resolved manifest: {e}")

        # Write credentials.env — a bash-sourceable file with generated values.
        # run_scenario.sh sources this to get real SAS tokens, JWTs, etc.

        # Always include a SAS token if blob storage is in this scenario
        if "SAS_TOKEN" not in values:
            try:
                sas = generate_sas_token()
                values["SAS_TOKEN"] = sas
                print(f"  SAS_TOKEN: {sas[:40]}...")
            except Exception as e:
                print(f"  WARNING: Could not generate SAS token: {e}")

        _write_credentials_env(output_dir, values)

    return resolved, values


def _write_credentials_env(output_dir: str, values: dict) -> None:
    """Write a bash-sourceable credentials.env with all generated values."""
    env_path = os.path.join(output_dir, "credentials.env")
    try:
        with open(env_path, "w") as f:
            f.write("# Auto-generated by init-seed. Source this in run_scenario.sh.\n")
            f.write("# DO NOT COMMIT — contains scenario-specific credentials.\n")
            for name, value in values.items():
                # Shell-safe quoting: single quotes, escape any embedded single quotes
                escaped = value.replace("'", "'\\''")
                f.write(f"SABER_{name}='{escaped}'\n")
        print(f"  Wrote credentials to: {env_path}")
    except Exception as e:
        print(f"  WARNING: Could not write credentials.env: {e}")


# =============================================================================
# Base Infrastructure Generation
# =============================================================================


def load_base_infra_template(path: str = "/app/base_infrastructure.template.yaml") -> dict:
    """Load base infrastructure template."""
    try:
        with open(path) as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        return {}


def generate_base_infrastructure(values: dict) -> dict:
    """Generate base_infrastructure with real values from template.

    Uses the same {{ PLACEHOLDER }} pattern as seed_manifest.template.yaml.
    """
    template = load_base_infra_template()

    if not template:
        # Fallback: minimal config with Azurite's well-known key
        return {
            "storage_accounts": [{"name": "proddata001", "keys": [{"name": "key1", "value": AZURITE_WELL_KNOWN_KEY}]}],
            "mock_service_defaults": {
                "connection_strings": {
                    "storage": f"DefaultEndpointsProtocol=https;AccountName=proddata001;AccountKey={AZURITE_WELL_KNOWN_KEY};EndpointSuffix=core.windows.net"
                }
            },
        }

    # Use the same template processing as seed_manifest
    base_values = generate_all_values(template)
    resolved = resolve_placeholders(template, base_values)

    print("  Generated base infrastructure")
    return resolved


# =============================================================================
# Service Seeding
# =============================================================================


def get_storage_key(base_infra: dict, account_name: str = "proddata001") -> str:
    """Get storage account key from base infrastructure."""
    for storage in base_infra.get("storage_accounts", []):
        if storage.get("name") == account_name:
            keys = storage.get("keys", [])
            if keys:
                return keys[0].get("value", "")
    defaults = base_infra.get("mock_service_defaults", {})
    conn_str = defaults.get("connection_strings", {}).get("storage", "")
    if "AccountKey=" in conn_str:
        for part in conn_str.split(";"):
            if part.startswith("AccountKey="):
                return part.split("=", 1)[1]
    return ""


def _get_blob_auth_header(
    method: str, url: str, headers: dict, account_name: str, key: str, content_length: int = 0
) -> str:
    """Generate Azure Blob Storage SharedKey authorization header."""
    parsed = urlparse(url)
    x_ms_headers = sorted([(k.lower(), v) for k, v in headers.items() if k.lower().startswith("x-ms-")])
    canonicalized_headers = "\n".join([f"{k}:{v}" for k, v in x_ms_headers])
    path = parsed.path
    canonicalized_resource = f"/{account_name}{path}"
    if parsed.query:
        params = sorted([p.split("=") for p in parsed.query.split("&")])
        for param in params:
            if len(param) == 2:
                canonicalized_resource += f"\n{param[0]}:{param[1]}"
    content_type = headers.get("Content-Type", "")
    string_to_sign = f"{method}\n\n\n{content_length if content_length else ''}\n\n{content_type}\n\n\n\n\n\n\n{canonicalized_headers}\n{canonicalized_resource}"
    key_bytes = base64.b64decode(key)
    signature = base64.b64encode(hmac.new(key_bytes, string_to_sign.encode("utf-8"), hashlib.sha256).digest()).decode(
        "utf-8"
    )
    return f"SharedKey {account_name}:{signature}"


def _get_keyvault_token() -> str:
    """Get token from IMDS for KeyVault access."""
    imds_host = os.getenv("IMDS_HOST", "imds")
    try:
        resp = requests.get(
            f"http://{imds_host}:80/metadata/identity/oauth2/token",
            params={"api-version": "2019-08-01", "resource": "https://vault.azure.net"},
            headers={"Metadata": "true"},
            timeout=5,
        )
        return resp.json().get("access_token", "")
    except Exception:
        return ""


def _normalize_to_list(data) -> list:
    """Convert dict-keyed or list data to a list of dicts with 'name' key.

    Handles both formats:
      Dict: {"key": {"field": "val"}} → [{"name": "key", "field": "val"}]
      List: [{"name": "key", "field": "val"}] → passed through
    """
    if isinstance(data, dict):
        return [{"name": k, **v} if isinstance(v, dict) else {"name": k, "value": v} for k, v in data.items()]
    if isinstance(data, list):
        return data
    return []


def wait_for_services(services: dict | None = None, timeout: int = 30):
    """Wait for services to be healthy.

    Only waits for services that are actually present in the scenario. Each
    endpoint gets its own timeout budget so an absent optional service doesn't
    consume the full startup window for every service that follows.
    """
    normalized_services = services or {}
    endpoints = []

    def add_endpoint(service_key: str, host_env: str, default_host: str, port: int, name: str) -> None:
        if service_key not in normalized_services and not os.getenv(host_env):
            return
        endpoints.append((os.getenv(host_env, default_host), port, name))

    add_endpoint("azure-blob-storage", "AZURITE_HOST", "azurite", 10000, "Azurite")
    add_endpoint("azure-ad", "AZURE_AD_HOST", "azure-ad", 8080, "Azure AD")
    add_endpoint("azure-keyvault", "KEYVAULT_HOST", "keyvault", 443, "KeyVault")
    add_endpoint("azure-imds", "IMDS_HOST", "imds", 80, "IMDS")

    print("Waiting for services...")

    for host, port, name in endpoints:
        url = f"http://{host}:{port}/health" if port != 443 else f"https://{host}:{port}/health"
        if port == 10000:
            url = f"http://{host}:{port}"

        start = time.time()
        while time.time() - start < timeout:
            try:
                requests.get(url, timeout=2, verify=False)
                print(f"  [OK] {name}")
                break
            except Exception:
                time.sleep(2)
        else:
            print(f"  [TIMEOUT] {name}")


def seed_blob_storage(containers: list, base_infra: dict, account_name: str = "proddata001", label: str = ""):
    """Seed blob storage containers and files.

    Args:
        containers: List of container dicts with 'name', 'files' keys
        base_infra: Base infrastructure config (for storage key lookup)
        account_name: Storage account name (default: proddata001)
        label: Optional label for log messages (e.g., "Benign" for base infra)
    """
    key = get_storage_key(base_infra, account_name)
    if not key:
        print(f"  [SKIP] No storage key for {account_name}")
        return

    host = os.getenv("AZURITE_HOST", "azurite")
    base_url = f"http://{host}:10000/{account_name}"
    prefix = f"{label} " if label else ""

    for container_info in containers:
        container_name = container_info.get("name")
        if not container_name:
            continue

        # Create container
        url = f"{base_url}/{container_name}?restype=container"
        date_str = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
        headers = {"x-ms-version": "2021-06-08", "x-ms-date": date_str}
        if container_info.get("public_access"):
            headers["x-ms-blob-public-access"] = "container"
        headers["Authorization"] = _get_blob_auth_header("PUT", url, headers, account_name, key)

        try:
            resp = requests.put(url, headers=headers)
            if resp.status_code in (201, 409):
                print(f"  [OK] {prefix}Container: {container_name}")
            else:
                print(f"  [FAIL] Container {container_name}: HTTP {resp.status_code}")
                continue
        except Exception as e:
            print(f"  [FAIL] Container {container_name}: {e}")
            continue

        # Upload files (support both 'files' and 'blobs' keys)
        for file_info in container_info.get("blobs", container_info.get("files", [])):
            file_name = file_info.get("name")
            content = file_info.get("content", "")
            if isinstance(content, str):
                content = content.encode("utf-8")

            blob_url = f"{base_url}/{container_name}/{file_name}"
            date_str = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
            headers = {
                "x-ms-version": "2021-06-08",
                "x-ms-date": date_str,
                "x-ms-blob-type": "BlockBlob",
                "Content-Type": "text/plain",
            }
            headers["Authorization"] = _get_blob_auth_header("PUT", blob_url, headers, account_name, key, len(content))

            try:
                resp = requests.put(blob_url, data=content, headers=headers)
                if resp.status_code == 201:
                    print(f"    [OK] File: {file_name}")
                else:
                    print(f"    [FAIL] File {file_name}: HTTP {resp.status_code}")
            except Exception as e:
                print(f"    [FAIL] File {file_name}: {e}")


def seed_keyvault(secrets: list, label: str = ""):
    """Seed KeyVault secrets.

    Args:
        secrets: List of secret dicts with 'name', 'value' keys
        label: Optional label for log messages (e.g., "Benign" for base infra)
    """
    host = os.getenv("KEYVAULT_HOST", "keyvault")
    base_url = f"https://{host}:443"
    prefix = f"{label} " if label else ""

    for secret in secrets:
        secret_name = secret.get("name")
        secret_value = secret.get("value", "")

        url = f"{base_url}/admin/secrets/{secret_name}"
        try:
            resp = requests.put(
                url,
                json={"value": secret_value},
                headers={"Content-Type": "application/json"},
                verify=False,
            )
            if resp.status_code in (200, 201):
                print(f"  [OK] {prefix}Secret: {secret_name}")
            else:
                print(f"  [FAIL] Secret {secret_name}: HTTP {resp.status_code}")
        except Exception as e:
            print(f"  [FAIL] Secret {secret_name}: {e}")


def seed_keyvault_tokens(tokens: list):
    """Inject valid tokens into KeyVault so it accepts them for secret operations.

    KeyVault validates Bearer tokens against an injected list.
    Tokens can come from IMDS exposed_tokens, credentials grants_access_to,
    or the azure-keyvault service config's tokens field.
    """
    host = os.getenv("KEYVAULT_HOST", "keyvault")
    base_url = f"https://{host}:443"

    if not tokens:
        print("  [SKIP] No tokens to inject")
        return

    try:
        resp = requests.post(
            f"{base_url}/admin/tokens",
            json={"tokens": tokens},
            verify=False,
            timeout=5,
        )
        if resp.status_code == 200:
            print(f"  [OK] KeyVault tokens: {len(tokens)} valid token(s)")
        else:
            print(f"  [FAIL] KeyVault tokens: HTTP {resp.status_code}")
    except Exception as e:
        print(f"  [FAIL] KeyVault tokens: {e}")


def _collect_tokens_for_service(service_name: str, manifest: dict) -> list:
    """Collect all tokens that grant access to a given service.

    Sources (in order):
      1. credentials.<name>.grants_access_to includes service_name
      2. services.<service_name>.tokens list
      3. IMDS exposed_tokens (legacy path)
    """
    tokens = []
    seen = set()

    # From credentials grants_access_to
    for cred_name, cred in manifest.get("credentials", {}).items():
        if not isinstance(cred, dict):
            continue
        grants = cred.get("grants_access_to", [])
        if service_name in grants:
            val = cred.get("value", "")
            if val and val not in seen:
                tokens.append(val)
                seen.add(val)

    # From service config tokens list
    services = manifest.get("services", {})
    svc = services.get(service_name, {})
    for tok in svc.get("tokens", []):
        if tok and tok not in seen:
            tokens.append(tok)
            seen.add(tok)

    # From IMDS exposed_tokens (legacy)
    imds = services.get("azure-imds", services.get("imds", {}))
    for tok in imds.get("exposed_tokens", {}).values():
        if tok and tok not in seen:
            tokens.append(tok)
            seen.add(tok)

    return tokens


def seed_exchange(exchange_config: dict, label: str = ""):
    """Seed Exchange Online with tokens, app IDs, and mailbox data.

    Args:
        exchange_config: Dict with optional keys:
            - tokens: list of Bearer token strings to accept
            - app_ids: list of app IDs whose tokens are valid
            - mailboxes: dict of user_id -> mailbox data (folders, messages)
        label: Optional label for log messages
    """
    host = os.getenv("EXCHANGE_HOST", "exchange-online")
    port = os.getenv("EXCHANGE_PORT", "443")
    scheme = "https" if port == "443" else "http"
    base_url = f"{scheme}://{host}:{port}"
    prefix = f"{label} " if label else ""

    tokens = exchange_config.get("tokens", [])
    app_ids = exchange_config.get("app_ids", [])
    if tokens or app_ids:
        payload = {}
        if tokens:
            payload["tokens"] = tokens
        if app_ids:
            payload["app_ids"] = app_ids
        try:
            resp = requests.post(f"{base_url}/admin/tokens", json=payload,
                                 timeout=10, verify=False)
            print(f"  {prefix}Exchange tokens: {resp.status_code} "
                  f"({len(tokens)} tokens, {len(app_ids)} app_ids)")
        except Exception as e:
            print(f"  {prefix}Exchange tokens FAILED: {e}")

    mailboxes = exchange_config.get("mailboxes", {})
    if mailboxes:
        try:
            resp = requests.post(f"{base_url}/admin/mailboxes", json=mailboxes,
                                 timeout=10, verify=False)
            print(f"  {prefix}Exchange mailboxes: {resp.status_code} "
                  f"({len(mailboxes)} mailboxes)")
        except Exception as e:
            print(f"  {prefix}Exchange mailboxes FAILED: {e}")


def seed_azure_ad(service_principals: list, label: str = ""):
    """Seed Azure AD service principals.

    Args:
        service_principals: List of SP dicts with 'name'/'app_id', 'client_secret' keys
        label: Optional label for log messages (e.g., "Benign" for base infra)
    """
    host = os.getenv("AZURE_AD_HOST", "azure-ad")
    base_url = f"http://{host}:8080"
    prefix = f"{label} " if label else ""

    for sp in service_principals:
        # Support both formats: dict with name/app_id or client_id
        sp_name = sp.get("name") or sp.get("display_name") or sp.get("app_id", "unknown")
        sp_entry = {
            "app_id": sp.get("app_id") or sp.get("client_id", sp_name),
            "display_name": sp.get("display_name") or sp.get("name", sp_name),
            "description": sp.get("description", ""),
            "credentials": [{"type": "secret", "value": sp.get("client_secret", "")}],
        }
        api_permissions = sp.get("api_permissions") or sp.get("permissions") or []
        if isinstance(api_permissions, str):
            api_permissions = [api_permissions]
        if api_permissions:
            sp_entry["api_permissions"] = list(api_permissions)
        role_assignments = sp.get("role_assignments") or []
        if isinstance(role_assignments, str):
            role_assignments = [role_assignments]
        if role_assignments:
            sp_entry["role_assignments"] = list(role_assignments)
        try:
            resp = requests.post(f"{base_url}/admin/service-principals", json=sp_entry, timeout=5)
            if resp.status_code == 200:
                print(f"  [OK] {prefix}SP: {sp_name}")
            else:
                print(f"  [FAIL] SP {sp_name}: HTTP {resp.status_code}")
        except Exception as e:
            print(f"  [FAIL] SP {sp_name}: {e}")


def seed_identities(services: dict):
    """Seed the UPN→object_id directory into the azure-ad mock.

    Emitted attack telemetry (SigninLogs UserId, AuditLogs target ids) must
    reference the SAME object_id the seed_manifest + benign baseline use — not a
    fresh random uuid4. We collect every ``users`` block across services (each
    ``{upn: {object_id, ...}}``) and POST the {upn: object_id} map to the mock's
    /admin/identities endpoint, along with ATTACKER_IP so emitted telemetry uses
    the configured attacker source IP instead of the Docker bridge socket IP.
    """
    host = os.getenv("AZURE_AD_HOST", "azure-ad")
    base_url = f"http://{host}:8080"
    identities: dict = {}
    for sname, sval in (services or {}).items():
        if not isinstance(sval, dict):
            continue
        users = sval.get("users")
        if isinstance(users, dict):
            for upn, info in users.items():
                oid = (info or {}).get("object_id") if isinstance(info, dict) else None
                if upn and oid:
                    identities[str(upn)] = str(oid)
    attacker_ip = os.getenv("ATTACKER_IP")
    if not identities and not attacker_ip:
        return
    try:
        resp = requests.post(
            f"{base_url}/admin/identities",
            json={"identities": identities, "attacker_ip": attacker_ip},
            timeout=5,
        )
        if resp.status_code == 200:
            msg = f"  [OK] Identities: {len(identities)} user(s)"
            if attacker_ip:
                msg += f", attacker_ip={attacker_ip}"
            print(msg)
        else:
            print(f"  [FAIL] Identities: HTTP {resp.status_code}")
    except Exception as e:
        print(f"  [FAIL] Identities: {e}")


def seed_app_service(config: dict):
    """Seed App Service environment variables."""
    host = os.getenv("APP_SERVICE_HOST", "app-service")
    base_url = f"http://{host}:8080"

    # Inject environment variables (vulnerable endpoint is hardcoded to /_next/rsc)
    for var_name, var_value in config.get("env_vars", {}).items():
        try:
            requests.post(f"{base_url}/admin/env", json={var_name: var_value}, timeout=5)
            print(f"    [OK] Env: {var_name}")
        except Exception:
            pass


def seed_imds(config: dict):
    """Seed IMDS with custom tokens.

    Config structure:
        exposed_tokens:
            managed_identity: "eyJ..."  # Token returned for all resources
            https://management.azure.com/: "eyJ..."  # Resource-specific token
    """
    host = os.getenv("IMDS_HOST", "imds")
    base_url = f"http://{host}:80"

    exposed_tokens = config.get("exposed_tokens", {})
    if not exposed_tokens:
        return

    # Convert exposed_tokens to the format IMDS expects
    tokens = {}
    for token_name, token_value in exposed_tokens.items():
        # Handle both "managed_identity" style and URL-style keys
        tokens[token_name] = token_value

    try:
        resp = requests.post(
            f"{base_url}/admin/tokens",
            json={"tokens": tokens},
            timeout=5,
        )
        if resp.status_code == 200:
            print(f"  [OK] IMDS: {len(tokens)} token(s) injected")
        else:
            print(f"  [FAIL] IMDS tokens: HTTP {resp.status_code}")
    except Exception as e:
        print(f"  [FAIL] IMDS tokens: {e}")


def _merge_arm_manifest(arm_config: dict, arm_manifest: dict) -> None:
    """Merge scenario-specific ARM manifest into the ARM config.

    The seed_manifest arm-api section may define subscriptions with
    resource_groups and nested resources (storage accounts with keys, etc.).
    This function extracts those and merges them into the flat ARM config
    so that listKeys and other discovery endpoints return scenario data.
    """
    existing_rg_names = {rg["name"] for rg in arm_config.get("resource_groups", [])}
    storage_accounts = arm_config.setdefault("storage_accounts", [])
    existing_sa_names = {sa["name"] for sa in storage_accounts}

    def upsert_storage_account(
        *,
        name: str,
        resource_group: str,
        location: str,
        primary_key: str = "",
        secondary_key: str = "",
    ) -> None:
        if not name:
            return
        for account in storage_accounts:
            if account.get("name") != name:
                continue
            account["resource_group"] = resource_group or account.get("resource_group", "")
            account["location"] = location or account.get("location", "")
            if primary_key:
                account["primary_key"] = primary_key
            if secondary_key:
                account["secondary_key"] = secondary_key
            return

        storage_accounts.append(
            {
                "name": name,
                "resource_group": resource_group,
                "location": location,
                "primary_key": primary_key,
                "secondary_key": secondary_key,
            }
        )
        existing_sa_names.add(name)

    for sub in arm_manifest.get("subscriptions", []):
        # Update subscription info if not set
        if not arm_config.get("subscription"):
            arm_config["subscription"] = {
                "subscription_id": sub.get("subscription_id", ""),
                "display_name": sub.get("display_name", ""),
            }

        for rg in sub.get("resource_groups", []):
            rg_name = rg.get("name", "")
            rg_location = rg.get("location", "eastus")

            # Add resource group if not already present
            if rg_name and rg_name not in existing_rg_names:
                arm_config["resource_groups"].append(
                    {
                        "name": rg_name,
                        "location": rg_location,
                    }
                )
                existing_rg_names.add(rg_name)

            for storage_account in rg.get("storage_accounts", []):
                upsert_storage_account(
                    name=storage_account.get("name", ""),
                    resource_group=rg_name,
                    location=storage_account.get("location", rg_location),
                    primary_key=storage_account.get("primary_key", ""),
                    secondary_key=storage_account.get("secondary_key", ""),
                )

            # Extract resources (storage accounts, etc.)
            for resource in rg.get("resources", []):
                res_type = resource.get("type", "")
                res_name = resource.get("name", "")
                props = resource.get("properties", {})

                if "Storage/storageAccounts" in res_type:
                    keys_data = props.get("listKeys", {}).get("keys", [])
                    upsert_storage_account(
                        name=res_name,
                        resource_group=rg_name,
                        location=resource.get("location", rg_location),
                        primary_key=keys_data[0]["value"] if len(keys_data) > 0 else resource.get("primary_key", ""),
                        secondary_key=(
                            keys_data[1]["value"] if len(keys_data) > 1 else resource.get("secondary_key", "")
                        ),
                    )

    # Also merge tokens from ARM manifest
    for token in arm_manifest.get("tokens", []):
        if token:
            try:
                host = os.getenv("ARM_HOST", "arm")
                base_url = f"https://{host}:443"
                resp = requests.post(
                    f"{base_url}/admin/tokens",
                    json={"tokens": [token]},
                    timeout=5,
                    verify=False,
                )
                if resp.status_code == 200:
                    print("  [OK] ARM manifest token injected")
            except Exception:
                pass


def seed_arm(imds_config: dict, base_infra: dict, arm_manifest: dict = None,
             manifest: dict = None):
    """Seed ARM with valid tokens and infrastructure config.

    ARM validates Bearer tokens against injected list, and returns
    infrastructure data for discovery endpoints.

    Args:
        imds_config: IMDS service config from seed_manifest (for exposed_tokens).
        base_infra: Base infrastructure config (resource_groups, storage_accounts, etc.).
        arm_manifest: ARM service config from seed_manifest (subscriptions, resource_groups,
                      storage accounts with keys). Merged into the ARM config so that
                      scenario-specific resources are discoverable.
    """
    host = os.getenv("ARM_HOST", "arm")
    base_url = f"https://{host}:443"

    # Inject valid tokens (from IMDS + arm-api service config + credentials)
    # The manifest may name the token list ``tokens`` or ``authorized_tokens``
    # (both are the set of management-scoped Bearer tokens ARM should accept).
    all_tokens = list(arm_manifest.get("tokens", []))
    seen = set(all_tokens)
    for tok in arm_manifest.get("authorized_tokens", []):
        if tok not in seen:
            all_tokens.append(tok)
            seen.add(tok)
    # Also collect any credential whose ``grants_access_to`` includes ARM (the
    # token may be obtained mid-chain and only declared via the credential's
    # grant, not the arm-api service block). Covers both service-name spellings.
    if manifest:
        for svc_name in ("arm-api", "azure-arm"):
            for tok in _collect_tokens_for_service(svc_name, manifest):
                if tok and tok not in seen:
                    all_tokens.append(tok)
                    seen.add(tok)
        # Also accept every stolen oauth_token credential as a management-scoped
        # Bearer. A compromised user/SP token presented to ARM for a discovery
        # enumeration (T1580) is the common cloud case — the victim usually has
        # at least subscription Reader, so the read succeeds and is logged in
        # AzureActivity (the resources/read marker). Without this, a stolen token
        # whose ``grants_access_to`` names only a non-ARM service (e.g. a BEC
        # token granting exchange-online) is rejected before ARM logs anything,
        # dropping the T1580 telemetry. Capture-only: never weakens a real auth
        # signal — it just lets the genuine stolen token reach the control plane.
        for cred in manifest.get("credentials", {}).values():
            if not isinstance(cred, dict):
                continue
            if cred.get("type") == "oauth_token":
                val = cred.get("value", "")
                if val and val not in seen:
                    all_tokens.append(val)
                    seen.add(val)
    exposed_tokens = imds_config.get("exposed_tokens", {})
    for tok in exposed_tokens.values():
        if tok not in seen:
            all_tokens.append(tok)
            seen.add(tok)
    if all_tokens:
        try:
            resp = requests.post(
                f"{base_url}/admin/tokens",
                json={"tokens": all_tokens},
                timeout=5,
                verify=False,
            )
            if resp.status_code == 200:
                print(f"  [OK] ARM tokens: {len(all_tokens)} valid token(s)")
            else:
                print(f"  [FAIL] ARM tokens: HTTP {resp.status_code}")
        except Exception as e:
            print(f"  [FAIL] ARM tokens: {e}")

    # Inject infrastructure config for discovery
    if base_infra:
        # Extract only the fields ARM needs for discovery
        arm_config = {
            "subscription": base_infra.get("subscription", {}),
            "resource_groups": base_infra.get("resource_groups", []),
            "storage_accounts": [
                {
                    "name": sa["name"],
                    "resource_group": sa["resource_group"],
                    "location": sa["location"],
                    "primary_key": sa.get("primary_key", ""),
                    "secondary_key": sa.get("secondary_key", ""),
                }
                for sa in base_infra.get("storage_accounts", [])
            ],
            "key_vaults": [
                {"name": kv["name"], "resource_group": kv["resource_group"], "location": kv["location"]}
                for kv in base_infra.get("key_vaults", [])
            ],
            "function_apps": [
                {"name": fa["name"], "resource_group": fa["resource_group"]}
                for fa in base_infra.get("function_apps", [])
            ],
            "app_services": [
                {"name": app["name"], "resource_group": app["resource_group"]}
                for app in base_infra.get("app_services", [])
            ],
        }

        # Merge scenario-specific ARM manifest (subscriptions → RGs → resources)
        if arm_manifest:
            _merge_arm_manifest(arm_config, arm_manifest)

        try:
            resp = requests.post(
                f"{base_url}/admin/config",
                json=arm_config,
                timeout=5,
                verify=False,
            )
            if resp.status_code == 200:
                print(
                    f"  [OK] ARM config: {len(arm_config['storage_accounts'])} storage, "
                    f"{len(arm_config['key_vaults'])} vaults, {len(arm_config['app_services'])} apps"
                )
            else:
                print(f"  [FAIL] ARM config: HTTP {resp.status_code}")
        except Exception as e:
            print(f"  [FAIL] ARM config: {e}")


def seed_functions(imds_config: dict):
    """Seed Azure Functions with valid tokens.

    Functions validates Bearer tokens against injected list.
    This allows attackers with stolen IMDS tokens to access Functions.
    """
    host = os.getenv("FUNCTIONS_HOST", "azure-functions")
    base_url = f"http://{host}:7071"

    # Inject valid tokens
    exposed_tokens = imds_config.get("exposed_tokens", {})
    if exposed_tokens:
        tokens = list(exposed_tokens.values())
        try:
            resp = requests.post(
                f"{base_url}/admin/tokens",
                json={"tokens": tokens},
                timeout=5,
            )
            if resp.status_code == 200:
                print(f"  [OK] Functions tokens: {len(tokens)} valid token(s)")
            else:
                print(f"  [FAIL] Functions tokens: HTTP {resp.status_code}")
        except Exception as e:
            print(f"  [FAIL] Functions tokens: {e}")


def seed_domain_controller(dc_config: dict):
    """Seed domain controller with users, groups, SPNs."""
    if not dc_config:
        return

    host = os.getenv("DC_HOST", "domain-controller")
    base_url = f"http://{host}:8080"

    try:
        resp = requests.post(f"{base_url}/admin/config", json=dc_config, timeout=10)
        if resp.status_code == 200:
            users = len(dc_config.get("users", []))
            groups = len(dc_config.get("groups", []))
            spns = len(dc_config.get("service_principal_names", []))
            print(f"  [OK] Domain Controller: {users} users, {groups} groups, {spns} SPNs")
        else:
            print(f"  [FAIL] Domain Controller: HTTP {resp.status_code}")
    except Exception as e:
        print(f"  [FAIL] Domain Controller: {e}")


# =============================================================================
# Service key normalization
# =============================================================================

# Manifests may use docker-compose names (e.g. "imds") or canonical names
# (e.g. "azure-imds"). This map ensures dispatch always works.
SERVICE_ALIASES = {
    "imds": "azure-imds",
    "arm-api": "azure-arm",
    "azurite": "azure-blob-storage",
    "keyvault": "azure-keyvault",
    "ad": "azure-ad",
    "functions": "azure-functions",
    "app-service": "azure-app-service",
}


def normalize_service_keys(services: dict) -> dict:
    """Normalize service dict keys to canonical names."""
    return {SERVICE_ALIASES.get(k, k): v for k, v in services.items()}


# =============================================================================
# Main (for init container)
# =============================================================================


def main():
    """Main seeding entry point."""
    print("=" * 60)
    print("SABER-SIM Init Seed Container")
    print("=" * 60)

    # Check for template vs resolved manifest
    template_path = "/app/seed_manifest.template.yaml"
    manifest_path = "/app/seed_manifest.yaml"

    if os.path.exists(template_path):
        print("\nProcessing template...")
        manifest, values = load_and_resolve_template(template_path)
        base_infra = generate_base_infrastructure(values)
    elif os.path.exists(manifest_path):
        print("\nLoading pre-resolved manifest...")
        with open(manifest_path) as f:
            manifest = yaml.safe_load(f)
        base_infra = {}
        if os.path.exists("/app/base_infrastructure.yaml"):
            with open("/app/base_infrastructure.yaml") as f:
                base_infra = yaml.safe_load(f)
    else:
        print("ERROR: No seed_manifest.template.yaml or seed_manifest.yaml found!")
        return

    services = normalize_service_keys(manifest.get("services", {}))
    wait_for_services(services)

    print("\nSeeding scenario data...")

    # CRITICAL: Seed IMDS first so tokens are available for other services
    imds_config = services.get("azure-imds", {})
    if imds_config:
        print("\n[IMDS]")
        seed_imds(imds_config)

    # Inject tokens into KeyVault (from IMDS, credentials, and service config)
    if "azure-keyvault" in services:
        print("\n[KeyVault Token Injection]")
        kv_tokens = _collect_tokens_for_service("azure-keyvault", manifest)
        seed_keyvault_tokens(kv_tokens)

    # Seed scenario blob storage. Supports two manifest shapes:
    #   1) Legacy single-account:
    #        services.azure-blob-storage:
    #          account_name: proddata001
    #          containers: [...]   # or dict
    #   2) Multi-account list:
    #        services.azure-blob-storage:
    #          accounts:
    #            - account_name: proddata001
    #              containers: [...]
    #            - account_name: analyticsdata002
    #              containers: [...]
    if "azure-blob-storage" in services:
        print("\n[Blob Storage]")
        blob_cfg = services["azure-blob-storage"] or {}
        account_groups: list[tuple[str, list]] = []
        if isinstance(blob_cfg.get("accounts"), list):
            for acc in blob_cfg["accounts"]:
                if not isinstance(acc, dict):
                    continue
                acc_name = acc.get("account_name") or acc.get("name") or "proddata001"
                account_groups.append((acc_name, _normalize_to_list(acc.get("containers") or [])))
        else:
            acc_name = blob_cfg.get("account_name", "proddata001")
            account_groups.append((acc_name, _normalize_to_list(blob_cfg.get("containers") or [])))

        for acc_name, containers_list in account_groups:
            if not containers_list:
                continue
            print(f"  → account: {acc_name}")
            seed_blob_storage(containers_list, base_infra, account_name=acc_name)

    # Seed scenario keyvault secrets
    if "azure-keyvault" in services:
        print("\n[KeyVault Secrets]")
        secrets_raw = services["azure-keyvault"].get("secrets", [])
        secrets_list = _normalize_to_list(secrets_raw)
        seed_keyvault(secrets_list)

    # Seed scenario service principals
    if "azure-ad" in services:
        print("\n[Azure AD]")
        sps_raw = services["azure-ad"].get("service_principals", [])
        sps_list = _normalize_to_list(sps_raw)
        seed_azure_ad(sps_list)

    # Seed the UPN→object_id directory + attacker IP into the azure-ad mock so
    # emitted attack telemetry is entity-consistent with the benign baseline.
    print("\n[Identity Directory]")
    seed_identities(services)

    if "exchange-online" in services:
        print("\n[Exchange Online]")
        seed_exchange(services["exchange-online"])

    if "azure-app-service" in services:
        print("\n[App Service]")
        seed_app_service(services["azure-app-service"])

    if "azure-arm" in services:
        print("\n[ARM]")
        imds_config = services.get("azure-imds", {})
        arm_manifest = services.get("azure-arm", {})
        seed_arm(imds_config, base_infra, arm_manifest, manifest=manifest)

    if "azure-functions" in services:
        print("\n[Functions]")
        imds_config = services.get("azure-imds", {})
        seed_functions(imds_config)

    # Seed base infrastructure (benign baseline data)
    if base_infra:
        print("\n" + "-" * 40)
        print("Seeding base infrastructure...")

        # Seed benign blob containers from each storage account
        for storage_account in base_infra.get("storage_accounts", []):
            benign_containers = storage_account.get("benign_containers", [])
            if benign_containers:
                account_name = storage_account.get("name", "proddata001")
                print(f"\n[Base Blob: {account_name}]")
                seed_blob_storage(benign_containers, base_infra, account_name, "Benign")

        # Seed benign keyvault secrets from each vault
        for kv in base_infra.get("key_vaults", []):
            benign_secrets = kv.get("benign_secrets", [])
            if benign_secrets:
                print(f"\n[Base KeyVault: {kv.get('name')}]")
                seed_keyvault(benign_secrets, "Benign")

        # Seed benign service principals
        benign_sps = base_infra.get("benign_service_principals", [])
        if benign_sps:
            print("\n[Base Service Principals]")
            seed_azure_ad(benign_sps, "Benign")

        # Seed domain controller
        dc_config = base_infra.get("domain_controller", {})
        if dc_config:
            print("\n[Domain Controller]")
            seed_domain_controller(dc_config)

    print("\n" + "=" * 60)
    print("Seeding complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
