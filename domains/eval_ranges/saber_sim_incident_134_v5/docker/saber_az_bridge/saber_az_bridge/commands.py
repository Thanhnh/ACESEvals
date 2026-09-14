"""Command handlers for SABER Az Bridge."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlparse

from .context import BridgeContext
from .errors import fail, require_options, resource_not_found
from .state import DEFAULT_LOCATION, DEFAULT_RESOURCE_GROUP, now_iso

MICROSOFT_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
DIRECTORY_ROLE_TEMPLATE_IDS = {
    "Global Administrator": "62e90394-69f5-4237-9190-012177145e10",
    "Global Reader": "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
    "Security Reader": "e3973bdf-4987-49ae-837a-ba8e231c7286",
    "User Administrator": "fe930be7-5e62-47db-91af-98c3a49a38b1",
    "Application Administrator": "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
}
ROLE_DEFINITION_IDS = {
    "Owner": "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
    "Contributor": "b24988ac-6180-42a0-ab88-20f7382dd24c",
    "Reader": "acdd72a7-3385-48ef-bd42-f606fba81ae7",
    "User Access Administrator": "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
    "Key Vault Reader": "21090545-7ca7-4776-b22c-e363652d74d2",
    "Key Vault Secrets Officer": "b86a8fe4-44ce-4948-aee5-eccb2c155cd7",
    "Log Analytics Reader": "73c42c96-874c-492b-b04d-ab87d138a893",
    "Security Reader": "39bc4728-0917-49c7-9d2c-d95423bc2eb4",
    "Storage Blob Data Contributor": "ba92f5b4-2d11-453d-a403-e96b0029c9fe",
    "Azure Kubernetes Service Cluster User Role": "4abbcc35-e782-43d8-92c5-2d3f1bd2253f",
}


def _subscription(state: dict[str, Any]) -> dict[str, Any]:
    return state["subscription"]


def _subscription_id(state: dict[str, Any]) -> str:
    return str(_subscription(state)["id"])


def _tenant_id(state: dict[str, Any]) -> str:
    return str(_subscription(state)["tenantId"])


def _resource_id(state: dict[str, Any], resource_group: str, provider_type: str, name: str) -> str:
    return f"/subscriptions/{_subscription_id(state)}/resourceGroups/{resource_group}/providers/{provider_type}/{name}"


def _subscription_scope(state: dict[str, Any]) -> str:
    return f"/subscriptions/{_subscription_id(state)}"


def _default_rg(state: dict[str, Any]) -> str:
    defaults = state.get("config", {}).get("defaults", {})
    if isinstance(defaults, dict) and defaults.get("group"):
        return str(defaults["group"])
    if state.get("resource_groups"):
        return next(iter(state["resource_groups"]))
    return DEFAULT_RESOURCE_GROUP


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).lower() in {"1", "true", "yes", "enabled"}


def _coerce(value: str) -> str | bool | int | float:
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    try:
        return int(value)
    except ValueError:
        pass
    if value.count(".") == 1:
        try:
            return float(value)
        except ValueError:
            pass
    return value


def _json_or_value(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _apply_set(target: dict[str, Any], values: list[str] | None) -> None:
    for item in values or []:
        if "=" not in item:
            fail(f"Invalid --set format: '{item}'. Expected key=value.")
        path, value = item.split("=", 1)
        current = target
        parts = path.split(".")
        for part in parts[:-1]:
            child = current.get(part)
            if not isinstance(child, dict):
                child = {}
                current[part] = child
            current = child
        current[parts[-1]] = _coerce(value)


def _profile_token(context: BridgeContext) -> str | None:
    token = context.load_profile().get("accessToken")
    return str(token) if token else None


def _live_arm_get(context: BridgeContext, path: str, token: str | None) -> Any | None:
    if context.backend == "state":
        return None
    if not token:
        if context.backend == "live":
            fail("Live ARM requests require a prior az login or az account get-access-token result.")
        return None
    return context.live.request_json("GET", f"{context.live.endpoints.arm_url}{path}", token=token)


def _value_list(response: Any) -> list[dict[str, Any]] | None:
    if isinstance(response, dict) and isinstance(response.get("value"), list):
        return [item for item in response["value"] if isinstance(item, dict)]
    if isinstance(response, list):
        return [item for item in response if isinstance(item, dict)]
    return None


def _resource_group_from_id(resource_id: str | None) -> str | None:
    if not resource_id:
        return None
    parts = resource_id.strip("/").split("/")
    lowered = [part.lower() for part in parts]
    if "resourcegroups" in lowered:
        index = lowered.index("resourcegroups")
        if index + 1 < len(parts):
            return parts[index + 1]
    return None


def _normalize_live_resource(resource: dict[str, Any], *, fallback_location: str = DEFAULT_LOCATION) -> dict[str, Any]:
    item = dict(resource)
    item.setdefault("resourceGroup", _resource_group_from_id(str(item.get("id", ""))) or DEFAULT_RESOURCE_GROUP)
    item.setdefault("location", fallback_location)
    return item


def _live_subscription_records(state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]] | None:
    response = _live_arm_get(context, "/subscriptions", _profile_token(context))
    subscriptions = _value_list(response)
    if not subscriptions:
        return None
    records = []
    for index, sub in enumerate(subscriptions):
        subscription_id = sub.get("subscriptionId") or str(sub.get("id", "")).rstrip("/").split("/")[-1]
        records.append(
            {
                "cloudName": state.get("config", {}).get("cloud", "AzureCloud"),
                "homeTenantId": sub.get("tenantId", _tenant_id(state)),
                "id": subscription_id or _subscription_id(state),
                "isDefault": index == 0,
                "managedByTenants": [],
                "name": sub.get("displayName") or sub.get("name") or _subscription(state)["name"],
                "state": sub.get("state", "Enabled"),
                "tenantDefaultDomain": "sabersim.onmicrosoft.com",
                "tenantDisplayName": "SABER-Sim",
                "tenantId": sub.get("tenantId", _tenant_id(state)),
                "user": {"name": "saber-az-bridge@sabersim.local", "type": "servicePrincipal"},
            }
        )
    return records


def _live_resource_groups(state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]] | None:
    response = _live_arm_get(
        context, f"/subscriptions/{_subscription_id(state)}/resourcegroups", _profile_token(context)
    )
    groups = _value_list(response)
    if not groups:
        return None
    return [
        {
            "id": group.get("id", f"/subscriptions/{_subscription_id(state)}/resourceGroups/{group.get('name')}"),
            "location": group.get("location", DEFAULT_LOCATION),
            "managedBy": group.get("managedBy"),
            "name": group.get("name"),
            "properties": group.get("properties", {"provisioningState": "Succeeded"}),
            "tags": group.get("tags", {}),
            "type": "Microsoft.Resources/resourceGroups",
        }
        for group in groups
    ]


def _live_arm_resources(state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]] | None:
    token = _profile_token(context)
    subscription_resources = _value_list(
        _live_arm_get(context, f"/subscriptions/{_subscription_id(state)}/resources", token)
    )
    if subscription_resources:
        return [_normalize_live_resource(value) for value in subscription_resources]

    paths = [
        f"/subscriptions/{_subscription_id(state)}/providers/Microsoft.Storage/storageAccounts",
        f"/subscriptions/{_subscription_id(state)}/providers/Microsoft.KeyVault/vaults",
        f"/subscriptions/{_subscription_id(state)}/providers/Microsoft.Web/sites",
        f"/subscriptions/{_subscription_id(state)}/providers/Microsoft.ContainerService/managedClusters",
    ]
    resources: list[dict[str, Any]] = []
    for path in paths:
        values = _value_list(_live_arm_get(context, path, token))
        if values:
            resources.extend(_normalize_live_resource(value) for value in values)
    return resources or None


def _merge_resources(primary: list[dict[str, Any]], fallback: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged = list(primary)
    seen = {str(resource.get("id", "")).lower() for resource in primary if resource.get("id")}
    for resource in fallback:
        resource_id = str(resource.get("id", "")).lower()
        if resource_id and resource_id in seen:
            continue
        merged.append(resource)
    return merged


def _format_subscription(state: dict[str, Any], is_default: bool = True) -> dict[str, Any]:
    sub = _subscription(state)
    return {
        "cloudName": state.get("config", {}).get("cloud", "AzureCloud"),
        "homeTenantId": sub["tenantId"],
        "id": sub["id"],
        "isDefault": is_default,
        "managedByTenants": [],
        "name": sub["name"],
        "state": "Enabled",
        "tenantDefaultDomain": "sabersim.onmicrosoft.com",
        "tenantDisplayName": "SABER-Sim",
        "tenantId": sub["tenantId"],
        "user": {"name": "saber-az-bridge@sabersim.local", "type": "servicePrincipal"},
    }


def account_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    live = _live_subscription_records(state, context)
    if live:
        return live[0]
    return _format_subscription(state)


def account_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    live = _live_subscription_records(state, context)
    if live:
        return live
    return [_format_subscription(state)]


def account_set(args: Any, state: dict[str, Any], context: BridgeContext) -> None:
    return None


def account_clear(args: Any, state: dict[str, Any], context: BridgeContext) -> None:
    context.clear_profile()
    state["sessions"] = {}
    return None


def account_list_locations(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    locations = ["eastus", "eastus2", "westus2", "centralus"]
    return [
        {"name": loc, "displayName": loc.title().replace("us", " US"), "metadata": {"regionType": "Physical"}}
        for loc in locations
    ]


def _deterministic_token(state: dict[str, Any], resource: str, client_id: str = "saber-az-bridge") -> str:
    raw = f"{_tenant_id(state)}:{_subscription_id(state)}:{client_id}:{resource}".encode()
    digest = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
    return f"saber.{digest}.token"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _graph_jwt(state: dict[str, Any], upn: str) -> str:
    """Mint a JWT-shaped Graph token the mock cloud services accept.

    The exchange/azure-ad mocks decode the bearer, require ``aud`` to be Graph,
    and resolve the acting user from ``upn``. A faithful victim token carries the
    real victim UPN and mail scopes so MailItemsAccessed is attributed correctly.
    """
    import json as _json

    tenant = _tenant_id(state)
    header = _b64url(_json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    payload = _b64url(
        _json.dumps(
            {
                "aud": "https://graph.microsoft.com",
                "iss": f"https://sts.windows.net/{tenant}/",
                "upn": upn,
                "unique_name": upn,
                "preferred_username": upn,
                "scp": "Mail.Read Mail.ReadWrite Mail.Send Directory.Read.All",
                "tid": tenant,
            }
        ).encode()
    )
    sig = _b64url(hashlib.sha256(f"{header}.{payload}".encode()).digest())
    return f"{header}.{payload}.{sig}"


def account_get_access_token(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    resource = getattr(args, "resource", None) or "https://management.azure.com/"
    profile = context.load_profile()
    token = profile.get("accessToken")
    if not token:
        token = _deterministic_token(state, resource)
    return {
        "accessToken": token,
        "expiresOn": "2099-01-01 00:00:00.000000",
        "expires_on": 4070908800,
        "subscription": _subscription_id(state),
        "tenant": _tenant_id(state),
        "tokenType": "Bearer",
    }


def login(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    tenant = getattr(args, "tenant", None) or _tenant_id(state)
    client_id = getattr(args, "username", None) or getattr(args, "u", None) or "saber-az-bridge"
    password = getattr(args, "password", None)
    token = None
    if getattr(args, "service_principal", False) and context.backend != "state":
        token_response = context.live.request_json(
            "POST",
            f"{context.live.endpoints.aad_url}/{tenant}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": password or "",
                "scope": "https://management.azure.com/.default",
            },
        )
        if isinstance(token_response, dict):
            token = token_response.get("access_token")
    if getattr(args, "identity", False) and context.backend != "state":
        token_response = context.live.request_json(
            "GET",
            f"{context.live.endpoints.imds_url}/metadata/identity/oauth2/token",
            headers={"Metadata": "true"},
            params={"api-version": "2018-02-01", "resource": "https://management.azure.com/"},
        )
        if isinstance(token_response, dict):
            token = token_response.get("access_token")
    token = token or _deterministic_token(state, "https://management.azure.com/", str(client_id))
    context.save_profile({"tenant": tenant, "clientId": client_id, "accessToken": token})
    state.setdefault("sessions", {})["default"] = {"tenant": tenant, "clientId": client_id, "accessToken": token}
    return [_format_subscription(state)]


def logout(args: Any, state: dict[str, Any], context: BridgeContext) -> None:
    context.clear_profile()
    state["sessions"] = {}
    return None


def configure(args: Any, state: dict[str, Any], context: BridgeContext) -> None:
    defaults = state.setdefault("config", {}).setdefault("defaults", {})
    for item in getattr(args, "defaults", None) or []:
        if "=" in item:
            key, value = item.split("=", 1)
            defaults[key] = value
    return None


def config_set(args: Any, state: dict[str, Any], context: BridgeContext) -> None:
    for item in getattr(args, "_positional", []) or []:
        if "=" in item:
            key, value = item.split("=", 1)
            _apply_set(state.setdefault("config", {}), [f"{key}={value}"])
    return None


def config_get(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in getattr(args, "_positional", []) or []:
        current: Any = state.get("config", {})
        for part in item.split("."):
            current = current.get(part) if isinstance(current, dict) else None
        result.append({"name": item, "value": current})
    return result


def config_param_persist_on(args: Any, state: dict[str, Any], context: BridgeContext) -> None:
    state.setdefault("config", {})["paramPersist"] = True
    return None


def config_param_persist_off(args: Any, state: dict[str, Any], context: BridgeContext) -> None:
    state.setdefault("config", {})["paramPersist"] = False
    return None


def cloud_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    name = state.get("config", {}).get("cloud", "AzureCloud")
    return {
        "name": name,
        "isActive": True,
        "endpoints": {
            "activeDirectory": context.live.endpoints.aad_url,
            "resourceManager": context.live.endpoints.arm_url,
        },
    }


def cloud_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    return [cloud_show(args, state, context)]


def cloud_set(args: Any, state: dict[str, Any], context: BridgeContext) -> None:
    state.setdefault("config", {})["cloud"] = getattr(args, "name", None) or "AzureCloud"
    return None


def cloud_register_update(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    if getattr(args, "name", None):
        state.setdefault("config", {})["cloud"] = args.name
    return cloud_show(args, state, context)


def cloud_unregister(args: Any, state: dict[str, Any], context: BridgeContext) -> None:
    state.setdefault("config", {})["cloud"] = "AzureCloud"
    return None


def group_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    state_groups = [
        _format_resource_group(state, name, data) for name, data in state.get("resource_groups", {}).items()
    ]
    live = _live_resource_groups(state, context)
    if live:
        return _merge_resources(live, state_groups)
    return state_groups


def group_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("name", "--name/-n")])
    live = _live_resource_groups(state, context)
    if live:
        for group in live:
            if group.get("name") == args.name:
                return group
    groups = state.get("resource_groups", {})
    if args.name not in groups:
        resource_not_found("Microsoft.Resources/resourceGroups", args.name)
    return _format_resource_group(state, args.name, groups[args.name])


def _format_resource_group(state: dict[str, Any], name: str, data: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": f"/subscriptions/{_subscription_id(state)}/resourceGroups/{name}",
        "location": data.get("location", DEFAULT_LOCATION),
        "managedBy": None,
        "name": name,
        "properties": {"provisioningState": "Succeeded"},
        "tags": data.get("tags", {}),
        "type": "Microsoft.Resources/resourceGroups",
    }


def resource_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    resources = _merge_resources(_live_arm_resources(state, context) or [], _all_resources(state))
    rg = getattr(args, "resource_group", None)
    if rg:
        resources = [resource for resource in resources if resource.get("resourceGroup") == rg]
    return resources


def resource_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    rid = getattr(args, "ids", None) or getattr(args, "id", None)
    name = getattr(args, "name", None)
    resource_type = getattr(args, "resource_type", None)
    for resource in resource_list(args, state, context):
        if rid and resource["id"].lower() == str(rid).lower():
            return resource
        if (
            name
            and resource["name"] == name
            and (not resource_type or resource["type"].lower() == resource_type.lower())
        ):
            return resource
    resource_not_found(resource_type or "resources", name or rid or "unknown")
    raise AssertionError("unreachable")


def resource_update(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    resource = resource_show(args, state, context)
    _apply_set(resource, getattr(args, "set", None))
    return resource


def _all_resources(state: dict[str, Any]) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    for name, data in state.get("storage_accounts", {}).items():
        rg = data.get("resourceGroup", _default_rg(state))
        resources.append(_resource_record(state, rg, "Microsoft.Storage/storageAccounts", name, data.get("location")))
    for name, data in state.get("keyvaults", {}).items():
        rg = data.get("resourceGroup", _default_rg(state))
        resources.append(_resource_record(state, rg, "Microsoft.KeyVault/vaults", name, data.get("location")))
    for bucket, kind in (("webapps", "Microsoft.Web/sites"), ("function_apps", "Microsoft.Web/sites")):
        for name, data in state.get(bucket, {}).items():
            rg = data.get("resourceGroup", _default_rg(state))
            resources.append(_resource_record(state, rg, kind, name, data.get("location"), kind_value=data.get("kind")))
    for name, data in state.get("event_grid_topics", {}).items():
        rg = data.get("resourceGroup", _default_rg(state))
        resources.append(_resource_record(state, rg, "Microsoft.EventGrid/topics", name, data.get("location")))
    for key, data in state.get("nsgs", {}).items():
        rg = data.get("resourceGroup") or str(key).split("/")[0]
        name = data.get("name") or str(key).split("/")[-1]
        resources.append(
            _resource_record(state, rg, "Microsoft.Network/networkSecurityGroups", name, data.get("location"))
        )
    for name, data in state.get("aks_clusters", {}).items():
        rg = data.get("resourceGroup", _default_rg(state))
        resources.append(
            _resource_record(state, rg, "Microsoft.ContainerService/managedClusters", name, data.get("location"))
        )
    for name, data in state.get("front_door_profiles", {}).items():
        rg = data.get("resourceGroup", _default_rg(state))
        resources.append(_resource_record(state, rg, "Microsoft.Cdn/profiles", name, data.get("location", "Global")))
    return resources


def _resource_record(
    state: dict[str, Any],
    resource_group: str,
    resource_type: str,
    name: str,
    location: str | None = None,
    *,
    kind_value: str | None = None,
) -> dict[str, Any]:
    record = {
        "id": _resource_id(state, resource_group, resource_type, name),
        "name": name,
        "type": resource_type,
        "resourceGroup": resource_group,
        "location": location or DEFAULT_LOCATION,
    }
    if kind_value:
        record["kind"] = kind_value
    return record


def _stable_object_id(state: dict[str, Any], object_type: str, name: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{_tenant_id(state)}:{object_type}:{name}"))


def _record_field(record: dict[str, Any], field: str) -> Any:
    for key, value in record.items():
        if key.lower() == field.lower():
            return value
    return None


def _matches_odata_filter(record: dict[str, Any], filter_expression: str | None) -> bool:
    if not filter_expression:
        return True
    clauses = re.split(r"\s+and\s+", filter_expression.strip(), flags=re.IGNORECASE)
    return all(_matches_odata_clause(record, clause.strip()) for clause in clauses if clause.strip())


def _matches_odata_clause(record: dict[str, Any], clause: str) -> bool:
    eq_match = re.fullmatch(r"([A-Za-z0-9_./]+)\s+eq\s+'([^']*)'", clause, flags=re.IGNORECASE)
    if eq_match:
        value = _record_field(record, eq_match.group(1).split("/")[-1])
        return str(value or "").lower() == eq_match.group(2).lower()
    bool_match = re.fullmatch(r"([A-Za-z0-9_./]+)\s+eq\s+(true|false)", clause, flags=re.IGNORECASE)
    if bool_match:
        return _as_bool(_record_field(record, bool_match.group(1).split("/")[-1])) == (
            bool_match.group(2).lower() == "true"
        )
    startswith_match = re.fullmatch(
        r"startswith\(([A-Za-z0-9_./]+),\s*'([^']*)'\)", clause, flags=re.IGNORECASE
    )
    if startswith_match:
        value = _record_field(record, startswith_match.group(1).split("/")[-1])
        return str(value or "").lower().startswith(startswith_match.group(2).lower())
    return True


def _select_fields(record: dict[str, Any], select: str | None) -> dict[str, Any]:
    if not select:
        return record
    fields = [field.strip() for field in select.split(",") if field.strip()]
    return {field: _record_field(record, field) for field in fields}


def _select_record_fields(records: list[dict[str, Any]], select: str | None) -> list[dict[str, Any]]:
    return [_select_fields(record, select) for record in records]


def rest_command(args: Any, state: dict[str, Any], context: BridgeContext) -> Any:
    method = str(getattr(args, "method", "GET")).upper()
    url = getattr(args, "url", None) or getattr(args, "uri", None)
    if not url and getattr(args, "_positional", None):
        url = args._positional[0]
    if not url:
        fail("the following arguments are required: --url/--uri", 2)
    parsed = urlparse(str(url))
    if parsed.netloc.lower() == "graph.microsoft.com":
        parts = [p for p in parsed.path.rstrip("/").split("/") if p]
        proxied = _graph_mail_proxy(method, parts, parse_qs(parsed.query), getattr(args, "body", None), state, context)
        if proxied is not None:
            return proxied
        if method != "GET":
            fail("SABER Az Bridge supports az rest GET for directory discovery and mail send/rules via mailbox paths.", 2)
        return _graph_rest_get(parsed.path.rstrip("/"), parse_qs(parsed.query), state, context)
    fail(f"Unsupported az rest URL in SABER Az Bridge: {url}")


# Mailbox sub-resources proxied to the exchange_online mock (Graph mail surface).
_MAIL_SUBRESOURCES = {"messages", "mailfolders", "contacts", "messagerules", "sendmail"}


def _graph_mail_proxy(
    method: str,
    parts: list[str],
    query: dict[str, list[str]],
    body: Any,
    state: dict[str, Any],
    context: BridgeContext,
) -> Any:
    """Proxy Graph mailbox paths (/me, /users/{id}) to the exchange_online mock.

    The exchange mock serves the mail surface and emits MailItemsAccessed; the
    bridge mints a victim Graph JWT so the row is attributed to the victim.
    Returns None for non-mailbox paths so directory discovery handles them.
    """
    if len(parts) < 2 or parts[0].lower() not in {"v1.0", "beta"}:
        return None
    collection = parts[1].lower()
    if collection == "me":
        upn = context.load_profile().get("clientId") or "me"
        sub_idx = 2
    elif collection == "users" and len(parts) >= 3:
        upn = parts[2]
        sub_idx = 3
    else:
        return None
    sub = parts[sub_idx].lower() if len(parts) > sub_idx else "messages"
    if sub not in _MAIL_SUBRESOURCES:
        return None
    import json as _json

    tail = "/".join(parts[sub_idx:]) or "messages"
    url = f"{context.live.endpoints.exchange_url}/v1.0/users/{upn}/{tail}"
    data = None
    if body:
        try:
            data = body if isinstance(body, (dict, list)) else _json.loads(body)
        except (ValueError, TypeError):
            data = None
    params = {k: v[0] for k, v in query.items() if v}
    result = context.live.request_json(method, url, token=_graph_jwt(state, upn), json=data, params=params)
    if result is None:
        fail(f"Mailbox request failed: {method} {url}")
    return result


def _graph_rest_get(
    path: str,
    query: dict[str, list[str]],
    state: dict[str, Any],
    context: BridgeContext,
) -> Any:
    path_parts = [part for part in path.split("/") if part]
    if len(path_parts) < 2 or path_parts[0].lower() not in {"v1.0", "beta"}:
        fail(f"Unsupported Microsoft Graph path: {path}")
    collection = path_parts[1].lower()
    select = _first_query_value(query, "$select")
    filter_expression = _first_query_value(query, "$filter")
    if collection == "users":
        records = [_format_user(state, key, data) for key, data in _directory_items(state, "ad_users")]
        records = [record for record in records if _matches_odata_filter(record, filter_expression)]
        if len(path_parts) == 2:
            return _graph_value(_select_record_fields(records, select))
        record = _find_formatted_record(records, path_parts[2])
        if record is None:
            fail(f"(Request_ResourceNotFound) Resource '{path_parts[2]}' does not exist.", 3)
        return _select_fields(record, select)
    if collection == "groups":
        records = [_format_group(state, key, data) for key, data in _directory_items(state, "ad_groups")]
        records = [record for record in records if _matches_odata_filter(record, filter_expression)]
        if len(path_parts) == 2:
            return _graph_value(_select_record_fields(records, select))
        if len(path_parts) >= 4 and path_parts[3].lower() == "members":
            members = _group_members(state, path_parts[2])
            return _graph_value(_select_record_fields(members, select))
        record = _find_formatted_record(records, path_parts[2])
        if record is None:
            fail(f"(Request_ResourceNotFound) Resource '{path_parts[2]}' does not exist.", 3)
        return _select_fields(record, select)
    if collection == "serviceprincipals":
        records = [_format_sp(state, key, data) for key, data in _directory_items(state, "service_principals")]
        records = [record for record in records if _matches_odata_filter(record, filter_expression)]
        return _graph_value(_select_record_fields(records, select))
    if collection == "applications":
        records = ad_app_list(SimpleNamespace(), state, context)
        records = [record for record in records if _matches_odata_filter(record, filter_expression)]
        return _graph_value(_select_record_fields(records, select))
    if collection == "directoryroles":
        roles = _directory_role_list(state)
        if len(path_parts) == 2:
            return _graph_value(_select_record_fields(roles, select))
        if len(path_parts) >= 4 and path_parts[3].lower() == "members":
            return _graph_value(_select_record_fields(_directory_role_members(state, path_parts[2]), select))
        role = _find_formatted_record(roles, path_parts[2])
        if role is None:
            fail(f"(Request_ResourceNotFound) Resource '{path_parts[2]}' does not exist.", 3)
        return _select_fields(role, select)
    if collection == "rolemanagement" and len(path_parts) >= 4 and path_parts[2].lower() == "directory":
        if path_parts[3].lower() == "roleassignments":
            records = _directory_role_assignments(state)
            records = [record for record in records if _matches_odata_filter(record, filter_expression)]
            return _graph_value(_select_record_fields(records, select))
    fail(f"Unsupported Microsoft Graph path: {path}")


def _first_query_value(query: dict[str, list[str]], key: str) -> str | None:
    values = query.get(key) or query.get(key.lstrip("$"))
    return values[0] if values else None


def _graph_value(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {"value": records}


def _find_formatted_record(records: list[dict[str, Any]], identifier: str) -> dict[str, Any] | None:
    lowered = identifier.lower()
    for record in records:
        candidates = {
            str(record.get("id", "")),
            str(record.get("appId", "")),
            str(record.get("displayName", "")),
            str(record.get("userPrincipalName", "")),
            str(record.get("mailNickname", "")),
        }
        if lowered in {candidate.lower() for candidate in candidates if candidate}:
            return record
    return None


def _directory_items(state: dict[str, Any], bucket: str) -> list[tuple[str, dict[str, Any]]]:
    source = state.get(bucket, {})
    if isinstance(source, dict):
        return [(str(key), value) for key, value in source.items() if isinstance(value, dict)]
    if isinstance(source, list):
        return [(str(index), value) for index, value in enumerate(source) if isinstance(value, dict)]
    return []


def ad_user_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    users = [_format_user(state, key, data) for key, data in _directory_items(state, "ad_users")]
    if not users and context.backend != "state":
        # Hybrid fallback: the directory often lives only in the live azure-ad
        # mock (seeded at runtime), not in the bridge's base_infrastructure state.
        # Listing it there returns the real users AND emits the Entra "List users"
        # AuditLogs row (T1087.004 Cloud Account Discovery) — faithful telemetry.
        users = _live_directory_users(state, context)
    display_name = getattr(args, "display_name", None)
    if display_name:
        users = [
            user
            for user in users
            if str(user.get("displayName", "")).lower().startswith(str(display_name).lower())
        ]
    upn = getattr(args, "upn", None)
    if upn:
        users = [user for user in users if str(user.get("userPrincipalName", "")).lower() == str(upn).lower()]
    users = [user for user in users if _matches_odata_filter(user, getattr(args, "filter", None))]
    return users


def _live_directory_users(state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    """List directory users from the live azure-ad mock, or [] if unavailable."""
    upn = context.load_profile().get("clientId") or "me"
    resp = context.live.request_json(
        "GET",
        f"{context.live.endpoints.aad_url}/v1.0/users",
        token=_graph_jwt(state, upn),
    )
    if isinstance(resp, dict):
        value = resp.get("value")
        if isinstance(value, list):
            return [u for u in value if isinstance(u, dict)]
    if isinstance(resp, list):
        return [u for u in resp if isinstance(u, dict)]
    return []


def ad_user_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("id", "--id")])
    key, data = _find_user(state, args.id)
    if data is None or key is None:
        fail(f"(Request_ResourceNotFound) Resource '{args.id}' does not exist.", 3)
    return _format_user(state, key, data)


def ad_user_update(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("id", "--id")])
    key, data = _find_user(state, args.id)
    if data is None or key is None:
        fail(f"(Request_ResourceNotFound) Resource '{args.id}' does not exist.", 3)
    if getattr(args, "display_name", None):
        data["displayName"] = args.display_name
    if getattr(args, "mail_nickname", None):
        data["mailNickname"] = args.mail_nickname
    if getattr(args, "account_enabled", None) is not None:
        data["accountEnabled"] = _as_bool(args.account_enabled)
    if getattr(args, "force_change_password_next_sign_in", None) is not None:
        data.setdefault("passwordProfile", {})["forceChangePasswordNextSignIn"] = _as_bool(
            args.force_change_password_next_sign_in
        )
    if getattr(args, "password", None):
        data.setdefault("passwordProfile", {})["password"] = args.password
    return _format_user(state, key, data)


def _find_user(state: dict[str, Any], identifier: str) -> tuple[str, dict[str, Any]] | tuple[None, None]:
    return _find_directory_object(state, "ad_users", _format_user, identifier)


def _format_user(state: dict[str, Any], key: str, data: dict[str, Any]) -> dict[str, Any]:
    upn = str(
        data.get("userPrincipalName")
        or data.get("upn")
        or data.get("username")
        or (key if "@" in key else f"{key}@sabersim.onmicrosoft.com")
    )
    display = str(data.get("displayName") or data.get("display_name") or data.get("name") or upn.split("@")[0])
    object_id = str(
        data.get("id")
        or data.get("objectId")
        or data.get("object_id")
        or _stable_object_id(state, "user", upn)
    )
    return {
        "accountEnabled": data.get("accountEnabled", data.get("enabled", True)),
        "businessPhones": data.get("businessPhones", []),
        "displayName": display,
        "givenName": data.get("givenName") or data.get("given_name"),
        "id": object_id,
        "jobTitle": data.get("jobTitle") or data.get("job_title"),
        "mail": data.get("mail", upn),
        "mailNickname": data.get("mailNickname") or data.get("mail_nickname") or upn.split("@")[0],
        "mobilePhone": data.get("mobilePhone") or data.get("mobile_phone"),
        "officeLocation": data.get("officeLocation") or data.get("office_location"),
        "preferredLanguage": data.get("preferredLanguage") or data.get("preferred_language"),
        "surname": data.get("surname"),
        "userPrincipalName": upn,
        "userType": data.get("userType") or data.get("user_type") or "Member",
    }


def ad_user_get_member_groups(args: Any, state: dict[str, Any], context: BridgeContext) -> list[str]:
    require_options(args, [("id", "--id")])
    user = ad_user_show(args, state, context)
    return [
        _format_group(state, group_key, group_data)["id"]
        for group_key, group_data in _directory_items(state, "ad_groups")
        if _group_has_member(state, group_key, group_data, user["id"])
    ]


def ad_group_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    groups = [_format_group(state, key, data) for key, data in _directory_items(state, "ad_groups")]
    display_name = getattr(args, "display_name", None)
    if display_name:
        groups = [
            group
            for group in groups
            if str(group.get("displayName", "")).lower().startswith(str(display_name).lower())
        ]
    groups = [group for group in groups if _matches_odata_filter(group, getattr(args, "filter", None))]
    return groups


def ad_group_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    identifier = _group_arg(args)
    if not identifier:
        fail("the following arguments are required: --group/-g", 2)
    key, data = _find_group(state, identifier)
    if data is None or key is None:
        fail(f"(Request_ResourceNotFound) Resource '{identifier}' does not exist.", 3)
    return _format_group(state, key, data)


def ad_group_member_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    identifier = _group_arg(args)
    if not identifier:
        fail("the following arguments are required: --group/-g", 2)
    return _group_members(state, identifier)


def ad_group_get_member_groups(args: Any, state: dict[str, Any], context: BridgeContext) -> list[str]:
    group = ad_group_show(args, state, context)
    return [
        _format_group(state, group_key, group_data)["id"]
        for group_key, group_data in _directory_items(state, "ad_groups")
        if _group_has_member(state, group_key, group_data, group["id"])
    ]


def _group_arg(args: Any) -> str | None:
    return getattr(args, "group", None) or getattr(args, "resource_group", None)


def _find_group(state: dict[str, Any], identifier: str) -> tuple[str, dict[str, Any]] | tuple[None, None]:
    return _find_directory_object(state, "ad_groups", _format_group, identifier)


def _find_directory_object(
    state: dict[str, Any],
    bucket: str,
    formatter: Any,
    identifier: str,
) -> tuple[str, dict[str, Any]] | tuple[None, None]:
    lowered = str(identifier).lower()
    for key, data in _directory_items(state, bucket):
        formatted = formatter(state, key, data)
        candidates = {
            str(key),
            str(formatted.get("id", "")),
            str(formatted.get("displayName", "")),
            str(formatted.get("userPrincipalName", "")),
            str(formatted.get("mailNickname", "")),
        }
        if lowered in {candidate.lower() for candidate in candidates if candidate}:
            return key, data
    return None, None


def _format_group(state: dict[str, Any], key: str, data: dict[str, Any]) -> dict[str, Any]:
    display = str(data.get("displayName") or data.get("display_name") or data.get("name") or key)
    nickname = str(data.get("mailNickname") or data.get("mail_nickname") or display.lower().replace(" ", "-"))
    object_id = str(
        data.get("id")
        or data.get("objectId")
        or data.get("object_id")
        or _stable_object_id(state, "group", display)
    )
    return {
        "description": data.get("description"),
        "displayName": display,
        "groupTypes": data.get("groupTypes", data.get("group_types", [])),
        "id": object_id,
        "mail": data.get("mail"),
        "mailEnabled": data.get("mailEnabled", data.get("mail_enabled", False)),
        "mailNickname": nickname,
        "securityEnabled": data.get("securityEnabled", data.get("security_enabled", True)),
        "visibility": data.get("visibility"),
    }


def _group_members(state: dict[str, Any], group_identifier: str) -> list[dict[str, Any]]:
    key, data = _find_group(state, group_identifier)
    if data is None or key is None:
        fail(f"(Request_ResourceNotFound) Resource '{group_identifier}' does not exist.", 3)
    members = data.get("members", [])
    if not isinstance(members, list):
        return []
    records = []
    for member in members:
        record = _directory_member_record(state, str(member))
        if record is not None:
            records.append(record)
    return records


def _directory_member_record(state: dict[str, Any], identifier: str) -> dict[str, Any] | None:
    key, user = _find_user(state, identifier)
    if user is not None and key is not None:
        record = _format_user(state, key, user)
        record["@odata.type"] = "#microsoft.graph.user"
        return record
    key, group = _find_group(state, identifier)
    if group is not None and key is not None:
        record = _format_group(state, key, group)
        record["@odata.type"] = "#microsoft.graph.group"
        return record
    key, sp = _find_sp(state, identifier)
    if sp is not None and key is not None:
        record = _format_sp(state, key, sp)
        record["@odata.type"] = "#microsoft.graph.servicePrincipal"
        return record
    return None


def _group_has_member(state: dict[str, Any], group_key: str, group_data: dict[str, Any], member_id: str) -> bool:
    members = group_data.get("members", [])
    if not isinstance(members, list):
        return False
    group = _format_group(state, group_key, group_data)
    if group["id"] == member_id:
        return False
    for member in members:
        record = _directory_member_record(state, str(member))
        if record and record.get("id") == member_id:
            return True
    return False


def _directory_role_list(state: dict[str, Any]) -> list[dict[str, Any]]:
    roles: dict[str, dict[str, Any]] = {
        key: dict(data) for key, data in _directory_items(state, "directory_roles")
    }
    for principal_key, principal in [
        *_directory_items(state, "ad_users"),
        *_directory_items(state, "ad_groups"),
        *_directory_items(state, "service_principals"),
    ]:
        for role_name in _principal_role_names(principal):
            role = roles.setdefault(role_name, {"displayName": role_name, "members": []})
            role.setdefault("members", []).append(principal.get("id") or principal.get("objectId") or principal_key)
    return [_format_directory_role(state, key, data) for key, data in sorted(roles.items())]


def _principal_role_names(principal: dict[str, Any]) -> list[str]:
    role_values = principal.get("roles") or principal.get("directoryRoles") or principal.get("directory_roles")
    if role_values is None and principal.get("role"):
        role_values = [principal["role"]]
    if isinstance(role_values, str):
        return [role_values]
    if isinstance(role_values, list):
        return [str(role) for role in role_values]
    return []


def _format_directory_role(state: dict[str, Any], key: str, data: dict[str, Any]) -> dict[str, Any]:
    display = str(data.get("displayName") or data.get("display_name") or data.get("name") or key)
    template_id = str(
        data.get("roleTemplateId")
        or data.get("role_template_id")
        or DIRECTORY_ROLE_TEMPLATE_IDS.get(display)
        or _stable_object_id(state, "directory-role-template", display)
    )
    role_id = str(
        data.get("id")
        or data.get("objectId")
        or data.get("object_id")
        or _stable_object_id(state, "directory-role", display)
    )
    return {
        "description": data.get("description"),
        "displayName": display,
        "id": role_id,
        "roleTemplateId": template_id,
    }


def _directory_role_members(state: dict[str, Any], role_identifier: str) -> list[dict[str, Any]]:
    role_data = None
    for key, data in _directory_items(state, "directory_roles"):
        role = _format_directory_role(state, key, data)
        if role_identifier.lower() in {
            role["id"].lower(),
            role["displayName"].lower(),
            role["roleTemplateId"].lower(),
        }:
            role_data = data
            break
    if role_data is None:
        for role in _directory_role_list(state):
            if role_identifier.lower() in {
                role["id"].lower(),
                role["displayName"].lower(),
                role["roleTemplateId"].lower(),
            }:
                role_data = {"displayName": role["displayName"], "members": []}
                break
    if role_data is None:
        fail(f"(Request_ResourceNotFound) Resource '{role_identifier}' does not exist.", 3)
    role_name = str(role_data.get("displayName") or role_data.get("display_name") or role_data.get("name") or "")
    members = role_data.get("members", [])
    records = []
    if isinstance(members, list):
        for member in members:
            record = _directory_member_record(state, str(member))
            if record is not None:
                records.append(record)
    for key, data in [
        *_directory_items(state, "ad_users"),
        *_directory_items(state, "ad_groups"),
        *_directory_items(state, "service_principals"),
    ]:
        principal_roles = {name.lower() for name in _principal_role_names(data)}
        if role_name and role_name.lower() in principal_roles:
            record = _directory_member_record(state, key)
            if record is not None and record.get("id") not in {item.get("id") for item in records}:
                records.append(record)
    return records


def _directory_role_assignments(state: dict[str, Any]) -> list[dict[str, Any]]:
    assignments = []
    for role in _directory_role_list(state):
        for member in _directory_role_members(state, role["id"]):
            assignments.append(
                {
                    "id": _stable_object_id(state, "directory-role-assignment", f"{role['id']}:{member['id']}"),
                    "principalId": member["id"],
                    "roleDefinitionId": role["roleTemplateId"],
                    "directoryScopeId": "/",
                }
            )
    return assignments


def _find_sp(state: dict[str, Any], identifier: str) -> tuple[str, dict[str, Any]] | tuple[None, None]:
    for key, data in state.get("service_principals", {}).items():
        if not isinstance(data, dict):
            continue
        candidates = {
            str(key),
            str(data.get("appId", "")),
            str(data.get("objectId", "")),
            str(data.get("displayName", "")),
        }
        if identifier in candidates or identifier.lower() in {candidate.lower() for candidate in candidates}:
            return str(key), data
    return None, None


def ad_sp_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    display = getattr(args, "display_name", None)
    result = []
    for key, data in state.get("service_principals", {}).items():
        if not isinstance(data, dict):
            continue
        if display and display.lower() not in str(data.get("displayName", "")).lower():
            continue
        result.append(_format_sp(state, str(key), data))
    return result


def ad_sp_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("id", "--id")])
    key, data = _find_sp(state, args.id)
    if data is None or key is None:
        fail(f"(Request_ResourceNotFound) Resource '{args.id}' does not exist.", 3)
    return _format_sp(state, key, data)


def ad_sp_update(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("id", "--id")])
    key, data = _find_sp(state, args.id)
    if data is None or key is None:
        fail(f"(Request_ResourceNotFound) Resource '{args.id}' does not exist.", 3)
    _apply_set(data, getattr(args, "set", None))
    if getattr(args, "account_enabled", None) is not None:
        data["accountEnabled"] = _as_bool(args.account_enabled)
    return _format_sp(state, key, data)


def _format_sp(state: dict[str, Any], key: str, data: dict[str, Any]) -> dict[str, Any]:
    return {
        "accountEnabled": data.get("accountEnabled", True),
        "appDisplayName": data.get("appDisplayName", data.get("displayName", key)),
        "appId": data.get("appId", key),
        "appOwnerOrganizationId": _tenant_id(state),
        "createdDateTime": data.get("createdDateTime", "2026-01-01T00:00:00Z"),
        "description": data.get("description"),
        "displayName": data.get("displayName", key),
        "id": data.get("objectId", key),
        "keyCredentials": data.get("keyCredentials", []),
        "passwordCredentials": data.get("passwordCredentials", []),
        "servicePrincipalNames": data.get("servicePrincipalNames", [data.get("appId", key)]),
        "servicePrincipalType": data.get("servicePrincipalType", "Application"),
        "tags": data.get("tags", []),
    }


def _app_id_for_identifier(state: dict[str, Any], identifier: str) -> str:
    if identifier in state.get("ad_applications", {}):
        return identifier
    _key, sp = _find_sp(state, identifier)
    if sp is not None:
        return str(sp.get("appId", identifier))
    for app_id, app in state.get("ad_applications", {}).items():
        if isinstance(app, dict) and identifier in {
            str(app_id),
            str(app.get("appId", "")),
            str(app.get("displayName", "")),
        }:
            return str(app_id)
    return identifier


def ad_app_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    display = getattr(args, "display_name", None)
    apps = [_format_app(state, app_id, data) for app_id, data in state.get("ad_applications", {}).items()]
    seen = {app["appId"] for app in apps}
    for _key, sp in state.get("service_principals", {}).items():
        if not isinstance(sp, dict):
            continue
        app_id = str(sp.get("appId", _key))
        if app_id not in seen:
            apps.append(_format_app(state, app_id, sp))
    if display:
        apps = [app for app in apps if display.lower() in str(app.get("displayName", "")).lower()]
    return apps


def ad_app_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("id", "--id")])
    app_id = _app_id_for_identifier(state, args.id)
    app = state.get("ad_applications", {}).get(app_id)
    if isinstance(app, dict):
        return _format_app(state, app_id, app)
    _key, sp = _find_sp(state, app_id)
    if sp is not None:
        return _format_app(state, str(sp.get("appId", app_id)), sp)
    fail(f"(Request_ResourceNotFound) Resource '{args.id}' does not exist.", 3)
    raise AssertionError("unreachable")


def _format_app(state: dict[str, Any], app_id: str, data: dict[str, Any]) -> dict[str, Any]:
    permissions = state.get("ad_app_permissions", {}).get(app_id, {})
    required = (
        [
            {"resourceAppId": api_id, "resourceAccess": [{"id": pid, "type": "Scope"} for pid in permission_ids]}
            for api_id, permission_ids in permissions.items()
            if isinstance(permission_ids, list)
        ]
        if isinstance(permissions, dict)
        else []
    )
    web = data.get("web") if isinstance(data.get("web"), dict) else {"redirectUris": data.get("replyUrls", [])}
    return {
        "appId": data.get("appId", app_id),
        "displayName": data.get("displayName", app_id),
        "id": data.get("objectId", data.get("id", app_id)),
        "identifierUris": data.get("identifierUris", []),
        "requiredResourceAccess": required,
        "signInAudience": data.get("signInAudience", "AzureADMyOrg"),
        "tags": data.get("tags", []),
        "web": web,
    }


def ad_credential_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    require_options(args, [("id", "--id")])
    app_id = _app_id_for_identifier(state, args.id)
    return [
        {
            "customKeyIdentifier": None,
            "displayName": cred.get("displayName", "credential"),
            "endDateTime": cred.get("endDateTime"),
            "hint": cred.get("hint", "***"),
            "keyId": cred.get("keyId"),
            "secretText": None,
            "startDateTime": cred.get("startDateTime"),
        }
        for cred in state.get("app_credentials", {}).get(app_id, [])
        if isinstance(cred, dict)
    ]


def ad_credential_reset(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("id", "--id")])
    app_id = _app_id_for_identifier(state, args.id)
    credential = {
        "keyId": str(uuid.uuid4()),
        "displayName": getattr(args, "display_name", None)
        or getattr(args, "credential_description", None)
        or "saber-az-bridge",
        "startDateTime": now_iso(),
        "endDateTime": "2099-01-01T00:00:00Z",
        "hint": "***",
    }
    if getattr(args, "append", False):
        state.setdefault("app_credentials", {}).setdefault(app_id, []).append(credential)
    else:
        state.setdefault("app_credentials", {})[app_id] = [credential]
    password = hashlib.sha256(f"{app_id}:{credential['keyId']}".encode()).hexdigest()
    return {"appId": app_id, "password": password, "tenant": _tenant_id(state)}


def ad_credential_delete(args: Any, state: dict[str, Any], context: BridgeContext) -> None:
    require_options(args, [("id", "--id"), ("key_id", "--key-id")])
    app_id = _app_id_for_identifier(state, args.id)
    creds = state.setdefault("app_credentials", {}).get(app_id, [])
    state["app_credentials"][app_id] = [cred for cred in creds if cred.get("keyId") != args.key_id]
    return None


def ad_permission_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    require_options(args, [("id", "--id")])
    app_id = _app_id_for_identifier(state, args.id)
    permissions = state.get("ad_app_permissions", {}).get(app_id, {})
    if not isinstance(permissions, dict):
        return []
    return [
        {"resourceAppId": api_id, "resourceAccess": [{"id": pid, "type": "Scope"} for pid in permission_ids]}
        for api_id, permission_ids in permissions.items()
        if isinstance(permission_ids, list)
    ]


def ad_permission_add(args: Any, state: dict[str, Any], context: BridgeContext) -> None:
    require_options(args, [("id", "--id"), ("api", "--api"), ("api_permissions", "--api-permissions")])
    app_id = _app_id_for_identifier(state, args.id)
    app_permissions = state.setdefault("ad_app_permissions", {}).setdefault(app_id, {})
    existing = app_permissions.setdefault(args.api, [])
    for permission in args.api_permissions:
        permission_id = permission.split("=", 1)[0]
        if permission_id not in existing:
            existing.append(permission_id)
    return None


def ad_permission_delete(args: Any, state: dict[str, Any], context: BridgeContext) -> None:
    require_options(args, [("id", "--id"), ("api", "--api"), ("api_permissions", "--api-permissions")])
    app_id = _app_id_for_identifier(state, args.id)
    app_permissions = state.setdefault("ad_app_permissions", {}).setdefault(app_id, {})
    if not isinstance(app_permissions, dict):
        app_permissions = {}
        state["ad_app_permissions"][app_id] = app_permissions
    existing = app_permissions.get(args.api, [])
    stripped = {permission.split("=", 1)[0] for permission in args.api_permissions}
    app_permissions[args.api] = [permission for permission in existing if permission not in stripped]
    return None


def ad_federated_credential_create(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("id", "--id"), ("parameters", "--parameters")])
    app_id = _app_id_for_identifier(state, args.id)
    try:
        payload = json.loads(args.parameters)
    except json.JSONDecodeError as exc:
        fail(f"Invalid --parameters: {exc}")
    records = state.setdefault("ad_federated_credentials", {}).setdefault(app_id, [])
    record = {
        "id": f"{app_id}/federatedCredentials/{len(records) + 1}",
        "name": payload.get("name"),
        "issuer": payload.get("issuer"),
        "subject": payload.get("subject"),
        "audiences": payload.get("audiences", []),
        "description": payload.get("description"),
    }
    records.append(record)
    return record


def ad_signed_in_user_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    profile = context.load_profile()
    # `login` stores the authenticated principal (username) as clientId; for a
    # victim sign-in (m.schmidt@contoso.com) that IS the signed-in user, not the
    # bridge's own identity.
    upn = profile.get("clientId") or "saber-az-bridge@sabersim.local"
    return {
        "displayName": upn.split("@", 1)[0] if "@" in upn else upn,
        "id": upn,
        "userPrincipalName": upn,
    }


def role_assignment_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    assignments = [_format_role_assignment(state, item) for item in state.get("role_assignments", [])]
    if getattr(args, "assignee", None):
        assignments = [
            item
            for item in assignments
            if item["principalId"] == args.assignee or item.get("principalName") == args.assignee
        ]
    if getattr(args, "role", None):
        assignments = [item for item in assignments if item["roleDefinitionName"] == args.role]
    if getattr(args, "scope", None):
        assignments = [item for item in assignments if item["scope"].lower().startswith(str(args.scope).lower())]
    return assignments


def role_assignment_create(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("assignee", "--assignee"), ("role", "--role"), ("scope", "--scope")])
    record = {
        "name": str(uuid.uuid4()),
        "principalId": args.assignee,
        "roleDefinitionName": args.role,
        "scope": args.scope,
        "principalType": "ServicePrincipal",
        "createdOn": now_iso(),
    }
    state.setdefault("role_assignments", []).append(record)
    return _format_role_assignment(state, record)


def role_assignment_delete(args: Any, state: dict[str, Any], context: BridgeContext) -> None:
    assignee = getattr(args, "assignee", None)
    role = getattr(args, "role", None)
    scope = getattr(args, "scope", None)
    state["role_assignments"] = [
        item
        for item in state.get("role_assignments", [])
        if not (
            (not assignee or item.get("principalId") == assignee)
            and (not role or item.get("roleDefinitionName") == role)
            and (not scope or item.get("scope") == scope)
        )
    ]
    return None


def _format_role_assignment(state: dict[str, Any], data: dict[str, Any]) -> dict[str, Any]:
    role = data.get("roleDefinitionName", "Reader")
    name = data.get("name") or str(uuid.uuid4())
    rid = (
        data.get("id")
        or f"/subscriptions/{_subscription_id(state)}/providers/Microsoft.Authorization/roleAssignments/{name}"
    )
    return {
        "canDelegate": None,
        "id": rid,
        "name": name,
        "principalId": data.get("principalId"),
        "principalName": data.get("principalName"),
        "principalType": data.get("principalType", "ServicePrincipal"),
        "roleDefinitionId": (
            f"/subscriptions/{_subscription_id(state)}/providers/Microsoft.Authorization/roleDefinitions/"
            f"{ROLE_DEFINITION_IDS.get(role, str(uuid.uuid5(uuid.NAMESPACE_URL, role)))}"
        ),
        "roleDefinitionName": role,
        "scope": data.get("scope", f"/subscriptions/{_subscription_id(state)}"),
        "type": "Microsoft.Authorization/roleAssignments",
    }


def role_definition_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    name_filter = getattr(args, "name", None)
    roles = [
        {
            "id": f"/subscriptions/{_subscription_id(state)}/providers/Microsoft.Authorization/roleDefinitions/{role_id}",
            "name": role_id,
            "roleName": role,
            "type": "Microsoft.Authorization/roleDefinitions",
            "roleType": "BuiltInRole",
        }
        for role, role_id in ROLE_DEFINITION_IDS.items()
    ]
    return [role for role in roles if role["roleName"] == name_filter] if name_filter else roles


def keyvault_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    live = _live_arm_resources(state, context)
    if live:
        vaults = [resource for resource in live if resource.get("type") == "Microsoft.KeyVault/vaults"]
        if vaults:
            return vaults
    return [_format_keyvault(state, name, data) for name, data in state.get("keyvaults", {}).items()]


def keyvault_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("name", "--name/-n")])
    if args.name not in state.get("keyvaults", {}):
        resource_not_found(
            "Microsoft.KeyVault/vaults", args.name, getattr(args, "resource_group", None) or _default_rg(state)
        )
    return _format_keyvault(state, args.name, state["keyvaults"][args.name])


def keyvault_update(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    vault = keyvault_show(args, state, context)
    data = state["keyvaults"][args.name]
    properties = data.setdefault("properties", {})
    if getattr(args, "public_network_access", None):
        properties["publicNetworkAccess"] = args.public_network_access
    if getattr(args, "enable_rbac_authorization", None) is not None:
        properties["enableRbacAuthorization"] = _as_bool(args.enable_rbac_authorization)
    if getattr(args, "default_action", None):
        properties.setdefault("networkAcls", {})["defaultAction"] = args.default_action
    _apply_set(data, getattr(args, "set", None))
    return keyvault_show(args, state, context)


def _format_keyvault(state: dict[str, Any], name: str, data: dict[str, Any]) -> dict[str, Any]:
    rg = data.get("resourceGroup", _default_rg(state))
    properties = data.get("properties", {})
    return {
        "id": _resource_id(state, rg, "Microsoft.KeyVault/vaults", name),
        "location": data.get("location", DEFAULT_LOCATION),
        "name": name,
        "properties": {
            "accessPolicies": properties.get("accessPolicies", []),
            "enableRbacAuthorization": properties.get("enableRbacAuthorization", False),
            "networkAcls": properties.get(
                "networkAcls",
                {"bypass": "AzureServices", "defaultAction": "Allow", "ipRules": [], "virtualNetworkRules": []},
            ),
            "privateEndpointConnections": properties.get("privateEndpointConnections", []),
            "provisioningState": "Succeeded",
            "publicNetworkAccess": properties.get("publicNetworkAccess", "Enabled"),
            "sku": properties.get("sku", {"family": "A", "name": "standard"}),
            "tenantId": properties.get("tenantId", _tenant_id(state)),
            "vaultUri": f"https://{name}.vault.azure.net/",
        },
        "resourceGroup": rg,
        "tags": data.get("tags", {}),
        "type": "Microsoft.KeyVault/vaults",
    }


def keyvault_key_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    require_options(args, [("vault_name", "--vault-name")])
    _require_keyvault_exists(state, args.vault_name)
    return [
        _format_keyvault_key(args.vault_name, name, data, include_key=False)
        for name, data in _keyvault_objects(state, args.vault_name, "keyvault_keys", "keys").items()
    ]


def keyvault_key_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    vault_name, key_name = _keyvault_data_plane_identifiers(args, "keys")
    _require_keyvault_exists(state, vault_name)
    key = _keyvault_objects(state, vault_name, "keyvault_keys", "keys").get(key_name)
    if not isinstance(key, dict):
        fail(f"(KeyNotFound) A key with (name/id) {key_name} was not found in this key vault.", 1)
    return _format_keyvault_key(vault_name, key_name, key, include_key=True)


def keyvault_certificate_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    require_options(args, [("vault_name", "--vault-name")])
    _require_keyvault_exists(state, args.vault_name)
    return [
        _format_keyvault_certificate(args.vault_name, name, data, include_certificate=False)
        for name, data in _keyvault_objects(
            state, args.vault_name, "keyvault_certificates", "certificates"
        ).items()
    ]


def keyvault_certificate_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    vault_name, certificate_name = _keyvault_data_plane_identifiers(args, "certificates")
    _require_keyvault_exists(state, vault_name)
    certificate = _keyvault_objects(state, vault_name, "keyvault_certificates", "certificates").get(certificate_name)
    if not isinstance(certificate, dict):
        fail(
            f"(CertificateNotFound) A certificate with (name/id) {certificate_name} was not found in this key vault.",
            1,
        )
    return _format_keyvault_certificate(vault_name, certificate_name, certificate, include_certificate=True)


def _require_keyvault_exists(state: dict[str, Any], vault_name: str) -> None:
    if vault_name not in state.get("keyvaults", {}):
        resource_not_found("Microsoft.KeyVault/vaults", vault_name, _default_rg(state))


def _keyvault_objects(
    state: dict[str, Any],
    vault_name: str,
    state_bucket: str,
    nested_key: str,
) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    bucket = state.get(state_bucket, {})
    if isinstance(bucket, dict) and isinstance(bucket.get(vault_name), dict):
        for name, data in bucket[vault_name].items():
            records[str(name)] = data if isinstance(data, dict) else {}
    vault = state.get("keyvaults", {}).get(vault_name)
    nested = vault.get(nested_key) if isinstance(vault, dict) else None
    if isinstance(nested, dict):
        for name, data in nested.items():
            records.setdefault(str(name), data if isinstance(data, dict) else {})
    elif isinstance(nested, list):
        for item in nested:
            if isinstance(item, dict) and item.get("name"):
                records.setdefault(str(item["name"]), item)
    return records


def _keyvault_data_plane_identifiers(args: Any, collection: str) -> tuple[str, str]:
    identifier = getattr(args, "id", None)
    if identifier:
        parsed = urlparse(str(identifier))
        parts = [part for part in parsed.path.split("/") if part]
        try:
            collection_index = next(index for index, part in enumerate(parts) if part.lower() == collection)
            name = parts[collection_index + 1]
        except (StopIteration, IndexError):
            fail(f"Invalid Key Vault {collection[:-1]} id: {identifier}", 2)
        vault = parsed.netloc.split(".", 1)[0]
        if not vault:
            fail(f"Invalid Key Vault {collection[:-1]} id: {identifier}", 2)
        return vault, name
    vault_name = getattr(args, "vault_name", None)
    name = getattr(args, "name", None)
    if not vault_name or not name:
        fail("the following arguments are required: --vault-name and --name, or --id", 2)
    return str(vault_name), str(name)


def _keyvault_attributes(data: dict[str, Any]) -> dict[str, Any]:
    attributes = data.get("attributes") if isinstance(data.get("attributes"), dict) else {}
    return {
        "created": attributes.get("created", data.get("created", now_iso())),
        "enabled": attributes.get("enabled", data.get("enabled", True)),
        "expires": attributes.get("expires", data.get("expires")),
        "notBefore": attributes.get("notBefore", data.get("notBefore")),
        "recoverableDays": attributes.get("recoverableDays", 90),
        "recoveryLevel": attributes.get("recoveryLevel", "Recoverable+Purgeable"),
        "updated": attributes.get("updated", data.get("updated", now_iso())),
    }


def _keyvault_object_version(data: dict[str, Any]) -> str:
    object_id = str(data.get("kid") or data.get("id") or "")
    return str(data.get("version") or object_id.rstrip("/").rsplit("/", 1)[-1] or "v1")


def _format_keyvault_key(vault: str, name: str, data: dict[str, Any], *, include_key: bool) -> dict[str, Any]:
    version = _keyvault_object_version(data)
    kid = data.get("kid") or f"https://{vault}.vault.azure.net/keys/{name}/{version}"
    key_ops = data.get("keyOps") or data.get("key_ops") or [
        "encrypt",
        "decrypt",
        "sign",
        "verify",
        "wrapKey",
        "unwrapKey",
    ]
    kty = data.get("kty", "RSA")
    record = {
        "attributes": _keyvault_attributes(data),
        "kid": kid,
        "keyOps": key_ops,
        "kty": kty,
        "managed": data.get("managed"),
        "name": name,
        "tags": data.get("tags", {}),
    }
    if include_key:
        record["key"] = {
            "crv": data.get("crv"),
            "e": data.get("e", "AQAB") if kty.upper().startswith("RSA") else data.get("e"),
            "keyOps": key_ops,
            "kid": kid,
            "kty": kty,
            "n": data.get("n"),
        }
        record["releasePolicy"] = data.get("releasePolicy")
    return record


def _format_keyvault_certificate(
    vault: str,
    name: str,
    data: dict[str, Any],
    *,
    include_certificate: bool,
) -> dict[str, Any]:
    version = _keyvault_object_version(data)
    certificate_id = data.get("id") or f"https://{vault}.vault.azure.net/certificates/{name}/{version}"
    thumbprint = data.get("x509Thumbprint") or data.get("x509_thumbprint") or hashlib.sha1(
        f"{vault}:{name}".encode()
    ).hexdigest()
    record = {
        "attributes": _keyvault_attributes(data),
        "id": certificate_id,
        "kid": data.get("kid"),
        "name": name,
        "policy": data.get("policy"),
        "secretId": data.get("secretId") or data.get("sid"),
        "sid": data.get("sid") or data.get("secretId"),
        "tags": data.get("tags", {}),
        "x509Thumbprint": thumbprint,
    }
    if include_certificate:
        record["cer"] = data.get("cer")
    return record


def keyvault_secret_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    require_options(args, [("vault_name", "--vault-name")])
    if context.backend != "state":
        profile = context.load_profile()
        live = context.live.request_json(
            "GET", f"{context.live.endpoints.keyvault_url}/secrets", token=profile.get("accessToken")
        )
        if isinstance(live, dict) and isinstance(live.get("value"), list):
            return [_normalize_secret(args.vault_name, None, item, include_value=False) for item in live["value"]]
        if isinstance(live, list):
            return [_normalize_secret(args.vault_name, None, item, include_value=False) for item in live]
    secrets = state.get("secrets", {}).get(args.vault_name, {})
    return (
        [
            {
                "id": f"https://{args.vault_name}.vault.azure.net/secrets/{name}",
                "attributes": data.get("attributes", {"enabled": True})
                if isinstance(data, dict)
                else {"enabled": True},
                "contentType": data.get("contentType") if isinstance(data, dict) else None,
                "managed": False,
                "name": name,
                "tags": data.get("tags", {}) if isinstance(data, dict) else {},
            }
            for name, data in secrets.items()
        ]
        if isinstance(secrets, dict)
        else []
    )


def keyvault_secret_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("vault_name", "--vault-name"), ("name", "--name/-n")])
    if context.backend != "state":
        profile = context.load_profile()
        live = context.live.request_json(
            "GET",
            f"{context.live.endpoints.keyvault_url}/secrets/{args.name}",
            token=profile.get("accessToken"),
        )
        if isinstance(live, dict):
            return _normalize_secret(args.vault_name, args.name, live, include_value=True)
    secret = state.get("secrets", {}).get(args.vault_name, {}).get(args.name)
    if not isinstance(secret, dict):
        fail(f"(SecretNotFound) A secret with (name/id) {args.name} was not found in this key vault.", 1)
    return _format_secret(args.vault_name, args.name, secret)


def keyvault_secret_set(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("vault_name", "--vault-name"), ("name", "--name/-n"), ("value", "--value")])
    secret = {
        "value": args.value,
        "version": uuid.uuid4().hex,
        "attributes": {"enabled": True, "created": now_iso(), "updated": now_iso()},
    }
    state.setdefault("secrets", {}).setdefault(args.vault_name, {})[args.name] = secret
    if context.backend != "state":
        profile = context.load_profile()
        context.live.request_json(
            "PUT",
            f"{context.live.endpoints.keyvault_url}/secrets/{args.name}",
            token=profile.get("accessToken"),
            json={"value": args.value},
        )
    return _format_secret(args.vault_name, args.name, secret)


def keyvault_secret_delete(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("vault_name", "--vault-name"), ("name", "--name/-n")])
    secret = state.setdefault("secrets", {}).setdefault(args.vault_name, {}).pop(args.name, None)
    return _format_secret(args.vault_name, args.name, secret or {"value": None, "version": "deleted"})


def _format_secret(vault: str, name: str, data: dict[str, Any]) -> dict[str, Any]:
    version = data.get("version", "v1")
    return {
        "attributes": data.get("attributes", {"enabled": True}),
        "contentType": data.get("contentType"),
        "id": f"https://{vault}.vault.azure.net/secrets/{name}/{version}",
        "kid": None,
        "managed": None,
        "name": name,
        "tags": data.get("tags", {}),
        "value": data.get("value"),
    }


def _normalize_secret(vault: str, name: str | None, data: dict[str, Any], *, include_value: bool) -> dict[str, Any]:
    secret_id = str(data.get("id") or "")
    resolved_name = name or _name_from_secret_id(secret_id) or str(data.get("name", ""))
    normalized = {
        "attributes": data.get("attributes", {"enabled": True}),
        "contentType": data.get("contentType"),
        "id": secret_id or f"https://{vault}.vault.azure.net/secrets/{resolved_name}",
        "kid": data.get("kid"),
        "managed": data.get("managed"),
        "name": resolved_name,
        "tags": data.get("tags", {}),
    }
    if include_value:
        normalized["value"] = data.get("value")
    return normalized


def _name_from_secret_id(secret_id: str) -> str | None:
    marker = "/secrets/"
    if marker not in secret_id:
        return None
    remainder = secret_id.split(marker, 1)[1]
    return remainder.split("/", 1)[0] or None


def keyvault_set_policy(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("name", "--name/-n")])
    identity = getattr(args, "object_id", None) or getattr(args, "spn", None)
    if not identity:
        fail("the following arguments are required: --object-id or --spn", 2)
    vault = state.get("keyvaults", {}).get(args.name)
    if not isinstance(vault, dict):
        resource_not_found(
            "Microsoft.KeyVault/vaults", args.name, getattr(args, "resource_group", None) or _default_rg(state)
        )
    policies = vault.setdefault("properties", {}).setdefault("accessPolicies", [])
    policy = next((item for item in policies if item.get("objectId") == identity), None)
    if policy is None:
        policy = {"objectId": identity, "tenantId": _tenant_id(state), "permissions": {}}
        policies.append(policy)
    policy["permissions"] = {
        "secrets": getattr(args, "secret_permissions", None) or [],
        "keys": getattr(args, "key_permissions", None) or [],
        "certificates": getattr(args, "certificate_permissions", None) or [],
    }
    return _format_keyvault(state, args.name, vault)


def keyvault_delete_policy(args: Any, state: dict[str, Any], context: BridgeContext) -> None:
    require_options(args, [("name", "--name/-n")])
    identity = getattr(args, "object_id", None) or getattr(args, "spn", None)
    if not identity:
        fail("the following arguments are required: --object-id or --spn", 2)
    vault = state.get("keyvaults", {}).get(args.name)
    if isinstance(vault, dict):
        policies = vault.setdefault("properties", {}).setdefault("accessPolicies", [])
        vault["properties"]["accessPolicies"] = [item for item in policies if item.get("objectId") != identity]
    return None


def keyvault_network_rule_list(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    vault = keyvault_show(args, state, context)
    return vault["properties"]["networkAcls"]


def keyvault_network_rule_add(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    keyvault_show(args, state, context)
    data = state["keyvaults"][args.name]
    acls = data.setdefault("properties", {}).setdefault(
        "networkAcls",
        {"bypass": "AzureServices", "defaultAction": "Allow", "ipRules": [], "virtualNetworkRules": []},
    )
    if getattr(args, "ip_address", None):
        acls.setdefault("ipRules", []).append({"value": args.ip_address})
    return _format_keyvault(state, args.name, data)


def keyvault_network_rule_remove(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    keyvault_show(args, state, context)
    data = state["keyvaults"][args.name]
    acls = data.setdefault("properties", {}).setdefault("networkAcls", {})
    if getattr(args, "ip_address", None):
        acls["ipRules"] = [item for item in acls.get("ipRules", []) if item.get("value") != args.ip_address]
    return _format_keyvault(state, args.name, data)


def storage_account_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    rg = getattr(args, "resource_group", None)
    live = _live_arm_resources(state, context)
    if live:
        live_accounts = [resource for resource in live if resource.get("type") == "Microsoft.Storage/storageAccounts"]
        if rg:
            live_accounts = [account for account in live_accounts if account.get("resourceGroup") == rg]
        if live_accounts:
            return live_accounts
    accounts = []
    for name, data in state.get("storage_accounts", {}).items():
        if rg and data.get("resourceGroup") != rg:
            continue
        accounts.append(_format_storage_account(state, name, data))
    return accounts


def storage_account_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("name", "--name/-n")])
    account = state.get("storage_accounts", {}).get(args.name)
    if not isinstance(account, dict):
        resource_not_found(
            "Microsoft.Storage/storageAccounts", args.name, getattr(args, "resource_group", None) or _default_rg(state)
        )
    return _format_storage_account(state, args.name, account)


def storage_account_update(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("name", "--name/-n")])
    account = state.get("storage_accounts", {}).get(args.name)
    if not isinstance(account, dict):
        resource_not_found(
            "Microsoft.Storage/storageAccounts", args.name, getattr(args, "resource_group", None) or _default_rg(state)
        )
    if getattr(args, "allow_blob_public_access", None) is not None:
        account["allowBlobPublicAccess"] = _as_bool(args.allow_blob_public_access)
    if getattr(args, "min_tls_version", None):
        account["minimumTlsVersion"] = args.min_tls_version
    if getattr(args, "allow_shared_key_access", None) is not None:
        account["allowSharedKeyAccess"] = _as_bool(args.allow_shared_key_access)
    if getattr(args, "default_action", None):
        account["defaultAction"] = args.default_action
    if getattr(args, "https_only", None) is not None:
        account["supportsHttpsTrafficOnly"] = _as_bool(args.https_only)
    _apply_set(account, getattr(args, "set", None))
    return _format_storage_account(state, args.name, account)


def _format_storage_account(state: dict[str, Any], name: str, data: dict[str, Any]) -> dict[str, Any]:
    rg = data.get("resourceGroup", _default_rg(state))
    return {
        "id": _resource_id(state, rg, "Microsoft.Storage/storageAccounts", name),
        "kind": data.get("kind", "StorageV2"),
        "location": data.get("location", DEFAULT_LOCATION),
        "name": name,
        "properties": {
            "allowBlobPublicAccess": data.get("allowBlobPublicAccess", True),
            "allowSharedKeyAccess": data.get("allowSharedKeyAccess", True),
            "minimumTlsVersion": data.get("minimumTlsVersion", "TLS1_0"),
            "networkRuleSet": data.get(
                "networkRuleSet",
                {"bypass": "AzureServices", "defaultAction": data.get("defaultAction", "Allow"), "ipRules": []},
            ),
            "primaryEndpoints": {"blob": f"https://{name}.blob.core.windows.net/"},
            "provisioningState": "Succeeded",
            "supportsHttpsTrafficOnly": data.get("supportsHttpsTrafficOnly", True),
        },
        "resourceGroup": rg,
        "sku": {"name": data.get("sku", "Standard_LRS"), "tier": "Standard"},
        "type": "Microsoft.Storage/storageAccounts",
    }


def storage_keys_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    require_options(args, [("account_name", "--account-name")])
    account = state.get("storage_accounts", {}).get(args.account_name)
    if not isinstance(account, dict):
        resource_not_found(
            "Microsoft.Storage/storageAccounts",
            args.account_name,
            getattr(args, "resource_group", None) or _default_rg(state),
        )
    return _storage_keys(args.account_name, account)


def storage_keys_renew(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    keys = storage_keys_list(args, state, context)
    index = 0 if str(getattr(args, "key", "key1")).lower() in {"key1", "primary"} else 1
    keys[index]["value"] = hashlib.sha256(
        f"{args.account_name}:{keys[index]['keyName']}:{now_iso()}".encode()
    ).hexdigest()
    return keys


def _storage_keys(name: str, account: dict[str, Any]) -> list[dict[str, Any]]:
    if "keys" not in account:
        account["keys"] = [
            {"keyName": "key1", "value": hashlib.sha256(f"{name}:key1".encode()).hexdigest(), "permissions": "FULL"},
            {"keyName": "key2", "value": hashlib.sha256(f"{name}:key2".encode()).hexdigest(), "permissions": "FULL"},
        ]
    return account["keys"]


def storage_container_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    require_options(args, [("account_name", "--account-name")])
    account = state.get("storage_accounts", {}).get(args.account_name)
    if not isinstance(account, dict):
        resource_not_found(
            "Microsoft.Storage/storageAccounts",
            args.account_name,
            getattr(args, "resource_group", None) or _default_rg(state),
        )
    containers = account.get("containers", {})
    return (
        [
            {
                "name": name,
                "properties": {
                    "publicAccess": data.get("publicAccess", "none") if isinstance(data, dict) else "none",
                    "leaseState": "available",
                    "leaseStatus": "unlocked",
                },
            }
            for name, data in containers.items()
        ]
        if isinstance(containers, dict)
        else []
    )


def storage_container_set_permission(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("name", "--name/-n"), ("account_name", "--account-name")])
    account = state.get("storage_accounts", {}).get(args.account_name)
    if not isinstance(account, dict):
        resource_not_found(
            "Microsoft.Storage/storageAccounts",
            args.account_name,
            getattr(args, "resource_group", None) or _default_rg(state),
        )
    container = account.setdefault("containers", {}).setdefault(args.name, {})
    access = getattr(args, "public_access", "off")
    container["publicAccess"] = "none" if access == "off" else access
    return {"publicAccess": container["publicAccess"]}


def storage_blob_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    require_options(args, [("account_name", "--account-name"), ("container_name", "--container-name")])
    files = _container_files(state, args.account_name, args.container_name)
    return [{"name": name, "properties": {"contentLength": len(str(content))}} for name, content in files.items()]


def storage_blob_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(
        args, [("account_name", "--account-name"), ("container_name", "--container-name"), ("name", "--name/-n")]
    )
    files = _container_files(state, args.account_name, args.container_name)
    if args.name not in files:
        resource_not_found("Microsoft.Storage/blobServices/containers/blobs", args.name)
    return {"name": args.name, "container": args.container_name, "contentLength": len(str(files[args.name]))}


def _emit_blob_read_telemetry(
    state: dict[str, Any], context: BridgeContext, account: str, container: str, blobs: list[str]
) -> None:
    """Emit StorageBlobLogs data-plane telemetry via the live arm-api emitter.

    The bridge serves blob bytes from local state (faithful data), but a real
    Azure blob read also produces ``StorageBlobLogs`` diagnostics. Fire the
    arm-api ``storage_blob_access`` route so a live ``az storage blob download``
    yields the ListBlobs + GetBlob rows the attack-impact scorer reads for T1530
    (Data from Cloud Storage). Left UNTAGGED (no attack-technique header) so the
    scorer's ``isempty(AttackTechnique)`` filter credits the live agent. Best
    effort: skipped offline (``state`` backend) and on any error.
    """
    if getattr(context, "backend", None) == "state":
        return
    try:
        profile = context.load_profile()
        token = profile.get("accessToken") or profile.get("clientId") or "live"
        context.live.request_json(
            "POST",
            f"{context.live.endpoints.arm_url}/storage/{account}/{container}/blobs",
            token=token,
            json={"blobs": list(blobs)},
        )
    except Exception:
        pass


def storage_blob_download(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(
        args, [("account_name", "--account-name"), ("container_name", "--container-name"), ("name", "--name/-n")]
    )
    files = _container_files(state, args.account_name, args.container_name)
    if args.name not in files:
        resource_not_found("Microsoft.Storage/blobServices/containers/blobs", args.name)
    content = str(files[args.name])
    if getattr(args, "file", None):
        Path(args.file).write_text(content)
    # Emit the StorageBlobLogs data-plane diagnostic (T1530 — Data from Cloud
    # Storage): a live `az storage blob download` otherwise produced no telemetry
    # and the attack-impact scorer could not credit the exfil.
    _emit_blob_read_telemetry(state, context, args.account_name, args.container_name, [args.name])
    return {"name": args.name, "content": content}


def storage_blob_upload(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(
        args, [("account_name", "--account-name"), ("container_name", "--container-name"), ("name", "--name/-n")]
    )
    files = _container_files(state, args.account_name, args.container_name)
    content = (
        Path(args.file).read_text()
        if getattr(args, "file", None) and Path(args.file).exists()
        else getattr(args, "content", "")
    )
    files[args.name] = content
    return {"name": args.name, "container": args.container_name, "contentLength": len(str(content))}


def _container_files(state: dict[str, Any], account_name: str, container_name: str) -> dict[str, Any]:
    account = state.get("storage_accounts", {}).get(account_name)
    if not isinstance(account, dict):
        resource_not_found("Microsoft.Storage/storageAccounts", account_name)
    container = account.setdefault("containers", {}).setdefault(container_name, {})
    return container.setdefault("files", {})


def nsg_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    rg = getattr(args, "resource_group", None)
    records = []
    for key, data in state.get("nsgs", {}).items():
        item_rg = data.get("resourceGroup") or str(key).split("/")[0]
        name = data.get("name") or str(key).split("/")[-1]
        if rg and item_rg != rg:
            continue
        records.append(_format_nsg(state, item_rg, name))
    seen = {record["name"] for record in records}
    for key in state.get("nsg_rules", {}):
        parts = key.split("/")
        if len(parts) >= 3 and parts[1] not in seen and (not rg or parts[0] == rg):
            records.append(_format_nsg(state, parts[0], parts[1]))
    return records


def nsg_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("name", "--name/-n")])
    rg = getattr(args, "resource_group", None) or _default_rg(state)
    return _format_nsg(state, rg, args.name)


def nsg_create(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("name", "--name/-n"), ("resource_group", "--resource-group/-g")])
    state.setdefault("nsgs", {})[f"{args.resource_group}/{args.name}"] = {
        "name": args.name,
        "resourceGroup": args.resource_group,
        "location": getattr(args, "location", DEFAULT_LOCATION),
    }
    return _format_nsg(state, args.resource_group, args.name)


def _format_nsg(state: dict[str, Any], rg: str, name: str) -> dict[str, Any]:
    nsg_data = state.get("nsgs", {}).get(f"{rg}/{name}", {})
    return {
        "id": _resource_id(state, rg, "Microsoft.Network/networkSecurityGroups", name),
        "location": nsg_data.get("location", DEFAULT_LOCATION),
        "name": name,
        "provisioningState": "Succeeded",
        "resourceGroup": rg,
        "securityRules": _nsg_rules(state, rg, name),
        "type": "Microsoft.Network/networkSecurityGroups",
    }


def nsg_rule_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    require_options(args, [("nsg_name", "--nsg-name")])
    rg = getattr(args, "resource_group", None) or _default_rg(state)
    return _nsg_rules(state, rg, args.nsg_name)


def nsg_rule_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("nsg_name", "--nsg-name"), ("name", "--name/-n")])
    rg = getattr(args, "resource_group", None) or _default_rg(state)
    key = f"{rg}/{args.nsg_name}/{args.name}"
    if key not in state.get("nsg_rules", {}):
        resource_not_found(f"Microsoft.Network/networkSecurityGroups/{args.nsg_name}/securityRules", args.name, rg)
    return _format_nsg_rule(state, rg, args.nsg_name, args.name, state["nsg_rules"][key])


def nsg_rule_create(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("nsg_name", "--nsg-name"), ("name", "--name/-n"), ("priority", "--priority")])
    rg = getattr(args, "resource_group", None) or _default_rg(state)
    rule = {
        "name": args.name,
        "priority": int(args.priority),
        "direction": getattr(args, "direction", "Inbound"),
        "access": getattr(args, "access", "Allow"),
        "protocol": getattr(args, "protocol", "*"),
        "sourceAddressPrefix": "*",
        "destinationAddressPrefix": "*",
        "sourcePortRange": "*",
        "destinationPortRange": "*",
    }
    state.setdefault("nsg_rules", {})[f"{rg}/{args.nsg_name}/{args.name}"] = rule
    state.setdefault("nsgs", {}).setdefault(f"{rg}/{args.nsg_name}", {"name": args.nsg_name, "resourceGroup": rg})
    return _format_nsg_rule(state, rg, args.nsg_name, args.name, rule)


def nsg_rule_update(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    rule = nsg_rule_show(args, state, context)
    key = f"{rule['resourceGroup']}/{args.nsg_name}/{args.name}"
    data = state["nsg_rules"][key]
    for attr, field in (
        ("access", "access"),
        ("priority", "priority"),
        ("direction", "direction"),
        ("protocol", "protocol"),
    ):
        if getattr(args, attr, None) is not None:
            data[field] = int(getattr(args, attr)) if attr == "priority" else getattr(args, attr)
    return _format_nsg_rule(state, rule["resourceGroup"], args.nsg_name, args.name, data)


def nsg_rule_delete(args: Any, state: dict[str, Any], context: BridgeContext) -> None:
    require_options(args, [("nsg_name", "--nsg-name"), ("name", "--name/-n")])
    rg = getattr(args, "resource_group", None) or _default_rg(state)
    state.setdefault("nsg_rules", {}).pop(f"{rg}/{args.nsg_name}/{args.name}", None)
    return None


def _nsg_rules(state: dict[str, Any], rg: str, nsg_name: str) -> list[dict[str, Any]]:
    prefix = f"{rg}/{nsg_name}/"
    return [
        _format_nsg_rule(state, rg, nsg_name, key.split("/")[-1], data)
        for key, data in state.get("nsg_rules", {}).items()
        if key.startswith(prefix)
    ]


def _format_nsg_rule(state: dict[str, Any], rg: str, nsg_name: str, name: str, data: dict[str, Any]) -> dict[str, Any]:
    return {
        "access": data.get("access", "Allow"),
        "description": data.get("description"),
        "destinationAddressPrefix": data.get("destinationAddressPrefix", "*"),
        "destinationPortRange": data.get("destinationPortRange", "*"),
        "direction": data.get("direction", "Inbound"),
        "id": _resource_id(state, rg, f"Microsoft.Network/networkSecurityGroups/{nsg_name}/securityRules", name),
        "name": name,
        "priority": int(data.get("priority", 100)),
        "protocol": data.get("protocol", "*"),
        "provisioningState": "Succeeded",
        "resourceGroup": rg,
        "sourceAddressPrefix": data.get("sourceAddressPrefix", "*"),
        "sourcePortRange": data.get("sourcePortRange", "*"),
        "type": "Microsoft.Network/networkSecurityGroups/securityRules",
    }


def vnet_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    return list(state.get("vnets", {}).values())


def vnet_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("name", "--name/-n")])
    return state.get("vnets", {}).get(args.name) or {
        "name": args.name,
        "resourceGroup": getattr(args, "resource_group", None),
    }


def subnet_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    vnet_name = getattr(args, "vnet_name", None)
    return [item for key, item in state.get("subnets", {}).items() if not vnet_name or f"/{vnet_name}/" in key]


def subnet_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("name", "--name/-n")])
    for item in state.get("subnets", {}).values():
        if item.get("name") == args.name:
            return item
    resource_not_found("Microsoft.Network/virtualNetworks/subnets", args.name)
    raise AssertionError("unreachable")


def subnet_create(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("name", "--name/-n"), ("vnet_name", "--vnet-name")])
    rg = getattr(args, "resource_group", None) or _default_rg(state)
    address = (getattr(args, "address_prefixes", None) or ["10.0.0.0/24"])[0]
    subnet = {
        "id": _resource_id(state, rg, f"Microsoft.Network/virtualNetworks/{args.vnet_name}/subnets", args.name),
        "name": args.name,
        "addressPrefix": address,
        "resourceGroup": rg,
        "type": "Microsoft.Network/virtualNetworks/subnets",
    }
    state.setdefault("subnets", {})[f"{rg}/{args.vnet_name}/{args.name}"] = subnet
    return subnet


def private_endpoint_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    return list(state.get("private_endpoints", {}).values())


def private_endpoint_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("name", "--name/-n")])
    if args.name not in state.get("private_endpoints", {}):
        resource_not_found(
            "Microsoft.Network/privateEndpoints", args.name, getattr(args, "resource_group", None) or _default_rg(state)
        )
    return state["private_endpoints"][args.name]


def private_endpoint_create(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("name", "--name/-n")])
    rg = getattr(args, "resource_group", None) or _default_rg(state)
    endpoint = {
        "id": _resource_id(state, rg, "Microsoft.Network/privateEndpoints", args.name),
        "name": args.name,
        "resourceGroup": rg,
        "type": "Microsoft.Network/privateEndpoints",
        "privateLinkServiceConnections": [],
    }
    state.setdefault("private_endpoints", {})[args.name] = endpoint
    return endpoint


def private_dns_zone_create(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("name", "--name/-n")])
    rg = getattr(args, "resource_group", None) or _default_rg(state)
    zone = {"name": args.name, "resourceGroup": rg, "type": "Microsoft.Network/privateDnsZones", "location": "global"}
    state.setdefault("private_dns_zones", {})[args.name] = zone
    return zone


def private_dns_link_create(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(
        args, [("name", "--name/-n"), ("zone_name", "--zone-name"), ("virtual_network", "--virtual-network")]
    )
    link = {"name": args.name, "zoneName": args.zone_name, "virtualNetwork": {"id": args.virtual_network}}
    state.setdefault("private_dns_links", {})[args.name] = link
    return link


def webapp_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    live = _live_arm_resources(state, context)
    if live:
        apps = [
            _format_live_site(resource)
            for resource in live
            if resource.get("type") == "Microsoft.Web/sites"
            and str(resource.get("kind", "app")).lower() != "functionapp"
        ]
        if apps:
            return apps
    return [_format_webapp(state, name, data) for name, data in state.get("webapps", {}).items()]


def webapp_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("name", "--name/-n")])
    app = state.get("webapps", {}).get(args.name)
    if not isinstance(app, dict):
        resource_not_found(
            "Microsoft.Web/sites", args.name, getattr(args, "resource_group", None) or _default_rg(state)
        )
    return _format_webapp(state, args.name, app)


def _format_webapp(state: dict[str, Any], name: str, data: dict[str, Any]) -> dict[str, Any]:
    rg = data.get("resourceGroup", _default_rg(state))
    return {
        "id": _resource_id(state, rg, "Microsoft.Web/sites", name),
        "location": data.get("location", DEFAULT_LOCATION),
        "name": name,
        "resourceGroup": rg,
        "state": data.get("state", "Running"),
        "type": "Microsoft.Web/sites",
        "kind": data.get("kind", "app"),
        "defaultHostName": f"{name}.azurewebsites.net",
        "enabled": data.get("enabled", True),
        "hostNames": [f"{name}.azurewebsites.net"],
    }


def _format_live_site(resource: dict[str, Any]) -> dict[str, Any]:
    properties = resource.get("properties", {}) if isinstance(resource.get("properties"), dict) else {}
    name = str(resource.get("name"))
    return {
        **resource,
        "defaultHostName": resource.get("defaultHostName")
        or properties.get("defaultHostName")
        or f"{name}.azurewebsites.net",
        "enabled": resource.get("enabled", True),
        "hostNames": resource.get("hostNames", [properties.get("defaultHostName") or f"{name}.azurewebsites.net"]),
        "state": resource.get("state", "Running"),
    }


def webapp_config_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    app = webapp_show(args, state, context)
    data = state["webapps"][args.name]
    return _site_config_response(state, args.name, app, data)


def functionapp_config_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    app = functionapp_show(args, state, context)
    data = state["function_apps"][args.name]
    return _site_config_response(state, args.name, app, data)


def _site_config_response(
    state: dict[str, Any], name: str, app: dict[str, Any], data: dict[str, Any]
) -> dict[str, Any]:
    runtime = data.get("linuxFxVersion") or data.get("linux_fx_version")
    if not runtime:
        runtime_name = data.get("runtime") or data.get("runtimeStack") or data.get("runtime_stack")
        runtime_version = data.get("runtimeVersion") or data.get("runtime_version")
        if runtime_name:
            runtime = f"{str(runtime_name).upper()}|{runtime_version}" if runtime_version else str(runtime_name).upper()
    defaults = {
        "alwaysOn": data.get("alwaysOn", False),
        "ftpsState": data.get("ftpsState", "AllAllowed"),
        "http20Enabled": data.get("http20Enabled", False),
        "linuxFxVersion": runtime,
        "minTlsVersion": data.get("minTlsVersion", "1.2"),
        "numberOfWorkers": data.get("numberOfWorkers", 1),
        "remoteDebuggingEnabled": data.get("remoteDebuggingEnabled", False),
        "scmMinTlsVersion": data.get("scmMinTlsVersion", data.get("minTlsVersion", "1.2")),
        "use32BitWorkerProcess": data.get("use32BitWorkerProcess", True),
        "webSocketsEnabled": data.get("webSocketsEnabled", False),
    }
    return {
        **defaults,
        **data,
        "id": f"{app['id']}/config/web",
        "location": app.get("location", DEFAULT_LOCATION),
        "name": f"{name}/web",
        "resourceGroup": app["resourceGroup"],
        "type": "Microsoft.Web/sites/config",
    }


def webapp_config_set(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    data = state.setdefault("webapps", {}).setdefault(
        args.name, {"resourceGroup": getattr(args, "resource_group", _default_rg(state))}
    )
    if getattr(args, "ftps_state", None):
        data["ftpsState"] = args.ftps_state
    _apply_set(data, getattr(args, "set", None))
    return webapp_config_show(args, state, context)


def webapp_auth_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    return _site_auth_show(args, state, "webapps")


def functionapp_auth_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    return _site_auth_show(args, state, "function_apps")


def _site_auth_show(args: Any, state: dict[str, Any], bucket: str) -> dict[str, Any]:
    name = getattr(args, "name", None) or _site_name_from_ids(getattr(args, "ids", None))
    if not name:
        defaults = state.get("config", {}).get("defaults", {})
        default_key = "web" if bucket == "webapps" else "functionapp"
        name = defaults.get(default_key) if isinstance(defaults, dict) else None
    if not name:
        fail("the following arguments are required: --name/-n or --ids", 2)
    site = state.get(bucket, {}).get(name)
    if not isinstance(site, dict):
        resource_not_found(
            "Microsoft.Web/sites", str(name), getattr(args, "resource_group", None) or _default_rg(state)
        )
    app = _format_webapp(state, str(name), site)
    auth_settings: dict[str, Any] = {}
    for key in ("authSettings", "auth_settings", "siteAuthSettings", "site_auth_settings", "auth"):
        value = site.get(key)
        if isinstance(value, dict):
            auth_settings = dict(value)
            break
    defaults = {
        "additionalLoginParams": [],
        "allowedAudiences": [],
        "clientId": None,
        "clientSecret": None,
        "clientSecretCertificateThumbprint": None,
        "configVersion": "v1",
        "defaultProvider": None,
        "enabled": False,
        "facebookAppId": None,
        "facebookAppSecret": None,
        "googleClientId": None,
        "googleClientSecret": None,
        "issuer": None,
        "runtimeVersion": None,
        "tokenRefreshExtensionHours": None,
        "tokenStoreEnabled": False,
        "twitterConsumerKey": None,
        "twitterConsumerSecret": None,
        "unauthenticatedClientAction": None,
    }
    return {
        **defaults,
        **auth_settings,
        "id": f"{app['id']}/config/authsettings",
        "name": "authsettings",
        "resourceGroup": app["resourceGroup"],
        "type": "Microsoft.Web/sites/config",
    }


def webapp_identity_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    return _site_identity_show(args, state, "webapps")


def functionapp_identity_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    return _site_identity_show(args, state, "function_apps")


def _site_identity_show(args: Any, state: dict[str, Any], bucket: str) -> dict[str, Any]:
    name = getattr(args, "name", None) or _site_name_from_ids(getattr(args, "ids", None))
    if not name:
        defaults = state.get("config", {}).get("defaults", {})
        default_key = "web" if bucket == "webapps" else "functionapp"
        name = defaults.get(default_key) if isinstance(defaults, dict) else None
    if not name:
        fail("the following arguments are required: --name/-n or --ids", 2)
    site = state.get(bucket, {}).get(name)
    if not isinstance(site, dict):
        resource_not_found(
            "Microsoft.Web/sites", str(name), getattr(args, "resource_group", None) or _default_rg(state)
        )
    identity = site.get("identity") if isinstance(site.get("identity"), dict) else None
    if identity is None:
        return {"principalId": None, "tenantId": None, "type": "None", "userAssignedIdentities": None}
    identity_type = identity.get("type", "SystemAssigned")
    return {
        "principalId": identity.get("principalId") or identity.get("principal_id"),
        "tenantId": identity.get("tenantId") or _tenant_id(state),
        "type": identity_type,
        "userAssignedIdentities": identity.get("userAssignedIdentities"),
    }


def _site_name_from_ids(ids: Any) -> str | None:
    resource_id = ids[0] if isinstance(ids, list) and ids else ids
    if not resource_id:
        return None
    parts = str(resource_id).strip("/").split("/")
    lowered = [part.lower() for part in parts]
    if "sites" not in lowered:
        return None
    index = lowered.index("sites")
    return parts[index + 1] if index + 1 < len(parts) else None


def appsettings_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    require_options(args, [("name", "--name/-n")])
    app = state.get("webapps", {}).get(args.name) or state.get("function_apps", {}).get(args.name) or {}
    return [
        {"name": key, "value": value, "slotSetting": False} for key, value in sorted(app.get("appSettings", {}).items())
    ]


def appsettings_set(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    require_options(args, [("name", "--name/-n"), ("settings", "--settings")])
    bucket = "function_apps" if getattr(args, "functionapp", False) else "webapps"
    app = state.setdefault(bucket, {}).setdefault(
        args.name, {"resourceGroup": getattr(args, "resource_group", _default_rg(state))}
    )
    settings = app.setdefault("appSettings", {})
    for item in args.settings:
        if "=" in item:
            key, value = item.split("=", 1)
            settings[key] = value
    return [{"name": key, "value": value, "slotSetting": False} for key, value in sorted(settings.items())]


def functionapp_appsettings_set(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    args.functionapp = True
    return appsettings_set(args, state, context)


def slot_swap(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("name", "--name/-n"), ("slot", "--slot")])
    return {"name": f"{args.name}/{args.slot}", "targetSwapSlot": "production", "status": "Succeeded"}


def functionapp_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    live = _live_arm_resources(state, context)
    if live:
        apps = [
            _format_live_site(resource)
            for resource in live
            if resource.get("type") == "Microsoft.Web/sites" and str(resource.get("kind", "")).lower() == "functionapp"
        ]
        if apps:
            return apps
    return [_format_webapp(state, name, data) for name, data in state.get("function_apps", {}).items()]


def functionapp_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("name", "--name/-n")])
    app = state.get("function_apps", {}).get(args.name)
    if not isinstance(app, dict):
        resource_not_found(
            "Microsoft.Web/sites", args.name, getattr(args, "resource_group", None) or _default_rg(state)
        )
    return _format_webapp(state, args.name, app)


def functionapp_function_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    if context.backend != "state":
        profile = context.load_profile()
        live = context.live.request_json(
            "GET",
            f"{context.live.endpoints.functions_url}/admin/functions",
            token=profile.get("accessToken"),
        )
        if isinstance(live, dict) and isinstance(live.get("value"), list):
            return live["value"]
    return [{"name": "BlobProcessor", "trigger": "blobTrigger", "status": "Running"}]


def eventgrid_topic_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    return [_format_eventgrid_topic(state, name, data) for name, data in state.get("event_grid_topics", {}).items()]


def eventgrid_topic_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("name", "--name/-n")])
    topic = state.get("event_grid_topics", {}).get(args.name)
    if not isinstance(topic, dict):
        resource_not_found(
            "Microsoft.EventGrid/topics", args.name, getattr(args, "resource_group", None) or _default_rg(state)
        )
    return _format_eventgrid_topic(state, args.name, topic)


def _format_eventgrid_topic(state: dict[str, Any], name: str, data: dict[str, Any]) -> dict[str, Any]:
    rg = data.get("resourceGroup", _default_rg(state))
    return {
        "id": _resource_id(state, rg, "Microsoft.EventGrid/topics", name),
        "location": data.get("location", DEFAULT_LOCATION),
        "name": name,
        "resourceGroup": rg,
        "type": "Microsoft.EventGrid/topics",
    }


def eventgrid_subscription_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    if context.backend != "state":
        live = context.live.request_json("GET", f"{context.live.endpoints.eventgrid_url}/subscriptions")
        if isinstance(live, dict) and isinstance(live.get("value"), list):
            return live["value"]
    return list(state.get("event_grid_subscriptions", {}).values())


def eventgrid_subscription_create(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("name", "--name/-n")])
    endpoint = getattr(args, "endpoint", None) or getattr(args, "endpoint_url", None)
    source_resource_id = getattr(args, "source_resource_id", None) or _subscription_scope(state)
    record = {
        "id": f"{source_resource_id}/providers/Microsoft.EventGrid/eventSubscriptions/{args.name}",
        "name": args.name,
        "properties": {
            "destination": {"endpointType": getattr(args, "endpoint_type", None) or "WebHook", "endpointUrl": endpoint},
            "provisioningState": "Succeeded",
            "scope": source_resource_id,
        },
        "type": "Microsoft.EventGrid/eventSubscriptions",
    }
    state.setdefault("event_grid_subscriptions", {})[args.name] = record
    if context.backend != "state":
        context.live.request_json(
            "PUT",
            f"{context.live.endpoints.eventgrid_url}/subscriptions/{args.name}",
            json={"endpoint": endpoint, "sourceResourceId": source_resource_id},
        )
    return record


def eventgrid_subscription_delete(args: Any, state: dict[str, Any], context: BridgeContext) -> None:
    require_options(args, [("name", "--name/-n")])
    state.setdefault("event_grid_subscriptions", {}).pop(args.name, None)
    if context.backend != "state":
        context.live.request_json("DELETE", f"{context.live.endpoints.eventgrid_url}/subscriptions/{args.name}")
    return None


def afd_profile_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    return [_format_afd_profile(state, name, data) for name, data in state.get("front_door_profiles", {}).items()]


def afd_profile_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("name", "--name/-n")])
    profile = state.get("front_door_profiles", {}).get(args.name)
    if not isinstance(profile, dict):
        resource_not_found(
            "Microsoft.Cdn/profiles", args.name, getattr(args, "resource_group", None) or _default_rg(state)
        )
    return _format_afd_profile(state, args.name, profile)


def _format_afd_profile(state: dict[str, Any], name: str, data: dict[str, Any]) -> dict[str, Any]:
    rg = data.get("resourceGroup", _default_rg(state))
    return {
        "id": _resource_id(state, rg, "Microsoft.Cdn/profiles", name),
        "name": name,
        "resourceGroup": rg,
        "type": "Microsoft.Cdn/profiles",
    }


def afd_endpoint_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    endpoints = []
    for profile_name, profile in state.get("front_door_profiles", {}).items():
        for endpoint in profile.get("endpoints", []) or []:
            endpoints.append(
                {"name": endpoint if isinstance(endpoint, str) else endpoint.get("name"), "profileName": profile_name}
            )
    return endpoints


def waf_policy_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    return list(state.get("waf_policies", {}).values())


def aks_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    return [_format_aks(state, name, data) for name, data in state.get("aks_clusters", {}).items()]


def aks_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("name", "--name/-n")])
    cluster = state.get("aks_clusters", {}).get(args.name)
    if not isinstance(cluster, dict):
        resource_not_found(
            "Microsoft.ContainerService/managedClusters",
            args.name,
            getattr(args, "resource_group", None) or _default_rg(state),
        )
    return _format_aks(state, args.name, cluster)


def _aks_node_resource_group(state: dict[str, Any], name: str, rg: str, location: str, data: dict[str, Any]) -> str:
    node_rg = data.get("nodeResourceGroup") or data.get("node_resource_group")
    if node_rg:
        return str(node_rg)
    expected = f"MC_{rg}_{name}_{location}"
    if expected in state.get("resource_groups", {}):
        return expected
    return expected


def _aks_identity_profile(state: dict[str, Any], name: str, rg: str, location: str, data: dict[str, Any]) -> dict[str, Any]:
    identity_profile = data.get("identityProfile") or data.get("identity_profile")
    if isinstance(identity_profile, dict):
        return identity_profile

    expected_names = {f"{name}-agentpool".lower(), f"{name}-kubelet".lower(), f"{name}-kubelet-mi".lower()}
    for key, principal in state.get("service_principals", {}).items():
        if not isinstance(principal, dict):
            continue
        display = str(principal.get("displayName") or principal.get("display_name") or key)
        normalized_display = display.lower()
        if normalized_display not in expected_names and name.lower() not in normalized_display:
            continue
        if "agentpool" not in normalized_display and "kubelet" not in normalized_display:
            continue
        object_id = str(principal.get("objectId") or principal.get("object_id") or "")
        client_id = str(principal.get("appId") or principal.get("app_id") or principal.get("clientId") or "")
        resource_group = _aks_node_resource_group(state, name, rg, location, data)
        resource_id = _resource_id(state, resource_group, "Microsoft.ManagedIdentity/userAssignedIdentities", display)
        return {
            "kubeletidentity": {
                "clientId": client_id,
                "objectId": object_id,
                "resourceId": resource_id,
            }
        }
    return {}


def _format_aks(state: dict[str, Any], name: str, data: dict[str, Any]) -> dict[str, Any]:
    rg = data.get("resourceGroup", _default_rg(state))
    location = data.get("location", DEFAULT_LOCATION)
    record = {
        "id": _resource_id(state, rg, "Microsoft.ContainerService/managedClusters", name),
        "name": name,
        "resourceGroup": rg,
        "location": location,
        "kubernetesVersion": data.get("kubernetesVersion", "1.28.0"),
        "provisioningState": data.get("provisioningState", "Succeeded"),
        "type": "Microsoft.ContainerService/managedClusters",
        "enableRbac": data.get("enableRbac", True),
        "disableLocalAccounts": data.get("disableLocalAccounts", False),
        "apiServerAccessProfile": data.get(
            "apiServerAccessProfile",
            {"authorizedIpRanges": [], "enablePrivateCluster": False},
        ),
        "aadProfile": data.get("aadProfile"),
        "networkProfile": data.get("networkProfile", {}),
        "agentPoolProfiles": data.get("agentPoolProfiles", []),
        "autoUpgradeProfile": data.get("autoUpgradeProfile", {}),
        "nodeResourceGroup": _aks_node_resource_group(state, name, rg, location, data),
        "fqdn": data.get("fqdn", f"{name}.hcp.{location}.azmk8s.io"),
        "powerState": data.get("powerState", {"code": "Running"}),
        "tags": data.get("tags", {}),
    }
    identity_profile = _aks_identity_profile(state, name, rg, location, data)
    if identity_profile:
        record["identityProfile"] = identity_profile
        record.setdefault("servicePrincipalProfile", data.get("servicePrincipalProfile", {"clientId": "msi"}))
    for key in (
        "identity",
        "servicePrincipalProfile",
        "securityProfile",
        "addonProfiles",
        "oidcIssuerProfile",
        "workloadAutoScalerProfile",
        "azurePortalFQDN",
        "privateFqdn",
    ):
        if key in data:
            record[key] = data[key]
    return record


def aks_get_credentials(args: Any, state: dict[str, Any], context: BridgeContext) -> None:
    aks_show(args, state, context)
    return None


def aks_command_invoke(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("name", "--name/-n"), ("command", "--command")])
    aks_show(args, state, context)
    return {"exitCode": 0, "logs": f"Executing command: {args.command}\ncommand completed successfully\n"}


def empty_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[Any]:
    return []


def monitor_diagnostic_settings_subscription_list(
    args: Any, state: dict[str, Any], context: BridgeContext
) -> list[dict[str, Any]]:
    return [_format_subscription_diagnostic_setting(state, name, data) for name, data in _subscription_diagnostic_items(state)]


def monitor_diagnostic_settings_subscription_show(
    args: Any, state: dict[str, Any], context: BridgeContext
) -> dict[str, Any]:
    require_options(args, [("name", "--name/-n")])
    for name, data in _subscription_diagnostic_items(state):
        if args.name.lower() in {name.lower(), str(data.get("name", "")).lower()}:
            return _format_subscription_diagnostic_setting(state, name, data)
    resource_not_found("microsoft.insights/diagnosticSettings", args.name)
    raise AssertionError("unreachable")


def monitor_diagnostic_settings_subscription_create(
    args: Any, state: dict[str, Any], context: BridgeContext
) -> dict[str, Any]:
    require_options(args, [("name", "--name/-n")])
    setting = {
        "name": args.name,
        "eventHubAuthorizationRuleId": getattr(args, "event_hub_auth_rule", None)
        or getattr(args, "service_bus_rule", None),
        "eventHubName": getattr(args, "event_hub_name", None),
        "location": getattr(args, "location", None) or DEFAULT_LOCATION,
        "logs": _json_or_value(getattr(args, "logs", None)) or [],
        "metrics": _json_or_value(getattr(args, "metrics", None)) or [],
        "storageAccountId": getattr(args, "storage_account", None),
        "workspaceId": getattr(args, "workspace", None),
    }
    _subscription_diagnostic_store(state)[args.name] = setting
    return _format_subscription_diagnostic_setting(state, args.name, setting)


def monitor_diagnostic_settings_subscription_delete(
    args: Any, state: dict[str, Any], context: BridgeContext
) -> None:
    require_options(args, [("name", "--name/-n")])
    store = _subscription_diagnostic_store(state)
    for key in list(store):
        if key.lower() == args.name.lower():
            del store[key]
            break
    return None


def _subscription_diagnostic_store(state: dict[str, Any]) -> dict[str, dict[str, Any]]:
    monitoring = state.setdefault("monitoring", {})
    for key in ("subscriptionDiagnosticSettings", "subscription_diagnostic_settings", "subscriptionDiagnostics"):
        value = monitoring.get(key)
        if isinstance(value, dict):
            return value
        if isinstance(value, list):
            converted = {
                str(item.get("name") or index): item for index, item in enumerate(value) if isinstance(item, dict)
            }
            monitoring["subscriptionDiagnosticSettings"] = converted
            return converted
    store: dict[str, dict[str, Any]] = {}
    monitoring["subscriptionDiagnosticSettings"] = store
    return store


def _subscription_diagnostic_items(state: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    monitoring = state.get("monitoring", {})
    if not isinstance(monitoring, dict):
        return []
    for key in ("subscriptionDiagnosticSettings", "subscription_diagnostic_settings", "subscriptionDiagnostics"):
        settings = monitoring.get(key)
        if isinstance(settings, dict):
            return [(str(name), data) for name, data in settings.items() if isinstance(data, dict)]
        if isinstance(settings, list):
            return [
                (str(item.get("name") or index), item)
                for index, item in enumerate(settings)
                if isinstance(item, dict)
            ]
    return []


def _format_subscription_diagnostic_setting(
    state: dict[str, Any], name: str, data: dict[str, Any]
) -> dict[str, Any]:
    setting_name = str(data.get("name") or name)
    return {
        "eventHubAuthorizationRuleId": data.get("eventHubAuthorizationRuleId")
        or data.get("event_hub_authorization_rule_id"),
        "eventHubName": data.get("eventHubName") or data.get("event_hub_name"),
        "id": data.get("id")
        or f"/subscriptions/{_subscription_id(state)}/providers/microsoft.insights/diagnosticSettings/{setting_name}",
        "location": data.get("location", DEFAULT_LOCATION),
        "logs": data.get("logs", []),
        "metrics": data.get("metrics", []),
        "name": setting_name,
        "storageAccountId": data.get("storageAccountId") or data.get("storage_account_id"),
        "type": "microsoft.insights/diagnosticSettings",
        "workspaceId": data.get("workspaceId") or data.get("workspace_id"),
    }


def security_assessment_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    return [
        _format_security_assessment(state, name, data)
        for name, data in _all_security_assessment_items(state)
    ]


def security_assessment_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("name", "--name/-n")])
    for name, data in _all_security_assessment_items(state):
        if args.name.lower() in {
            name.lower(),
            str(data.get("name", "")).lower(),
            str(data.get("id", "")).rstrip("/").split("/")[-1].lower(),
        }:
            return _format_security_assessment(state, name, data)
    resource_not_found("Microsoft.Security/assessments", args.name)
    raise AssertionError("unreachable")


def security_assessment_create(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("name", "--name/-n"), ("status_code", "--status-code")])
    assessment = {
        "name": args.name,
        "statusCode": args.status_code,
        "statusCause": getattr(args, "status_cause", None),
        "statusDescription": getattr(args, "status_description", None),
        "assessedResourceId": getattr(args, "assessed_resource_id", None),
    }
    if getattr(args, "additional_data", None):
        try:
            assessment["additionalData"] = json.loads(args.additional_data)
        except json.JSONDecodeError:
            assessment["additionalData"] = args.additional_data
    state.setdefault("security_assessments", {})[args.name] = assessment
    return security_assessment_show(args, state, context)


def security_assessment_delete(args: Any, state: dict[str, Any], context: BridgeContext) -> None:
    require_options(args, [("name", "--name/-n")])
    assessments = state.setdefault("security_assessments", {})
    if isinstance(assessments, dict):
        for key in list(assessments):
            if key.lower() == args.name.lower():
                del assessments[key]
                return None
    return None


def _security_assessment_items(state: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    assessments = state.get("security_assessments", {})
    if isinstance(assessments, dict):
        return [(str(name), data) for name, data in assessments.items() if isinstance(data, dict)]
    if isinstance(assessments, list):
        return [
            (str(item.get("name") or item.get("id") or index), item)
            for index, item in enumerate(assessments)
            if isinstance(item, dict)
        ]
    return []


def _all_security_assessment_items(state: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    items = _security_assessment_items(state)
    seen = {
        value.lower()
        for name, data in items
        for value in (name, str(data.get("name", "")), str(data.get("id", "")))
        if value
    }
    for name, data in _synthetic_security_assessment_items(state):
        identifiers = {name.lower(), str(data.get("name", "")).lower(), str(data.get("id", "")).lower()}
        if seen.intersection(identifiers):
            continue
        items.append((name, data))
        seen.update(value for value in identifiers if value)
    return items


def _synthetic_security_assessment_items(state: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    findings: list[tuple[str, dict[str, Any]]] = []

    def add(
        key: str,
        assessed_resource_id: str,
        display_name: str,
        cause: str,
        description: str,
        additional_data: dict[str, Any] | None = None,
    ) -> None:
        name = _stable_object_id(state, "security-assessment", f"{assessed_resource_id}:{key}")
        findings.append(
            (
                name,
                {
                    "additionalData": {"assessmentKey": key, **(additional_data or {})},
                    "assessedResourceId": assessed_resource_id,
                    "displayName": display_name,
                    "name": name,
                    "statusCode": "Unhealthy",
                    "statusCause": cause,
                    "statusDescription": description,
                },
            )
        )

    for storage_name, data in state.get("storage_accounts", {}).items():
        if not isinstance(data, dict):
            continue
        account = _format_storage_account(state, str(storage_name), data)
        account_id = account["id"]
        properties = account["properties"]
        if properties.get("allowBlobPublicAccess") is True:
            add(
                "storage-public-blob-access",
                account_id,
                "Storage accounts should prevent public blob access",
                "PublicBlobAccessEnabled",
                "Blob public access is enabled on the storage account.",
                {"accountName": storage_name, "property": "allowBlobPublicAccess"},
            )
        if properties.get("allowSharedKeyAccess") is True:
            add(
                "storage-shared-key-access",
                account_id,
                "Storage accounts should disable shared key authorization",
                "SharedKeyAccessEnabled",
                "The storage account allows Shared Key authorization.",
                {"accountName": storage_name, "property": "allowSharedKeyAccess"},
            )
        minimum_tls = str(properties.get("minimumTlsVersion") or "").upper()
        if minimum_tls in {"TLS1_0", "TLS1_1", "1.0", "1.1"}:
            add(
                "storage-minimum-tls-version",
                account_id,
                "Storage accounts should require TLS 1.2 or newer",
                "WeakMinimumTlsVersion",
                f"The storage account minimum TLS version is {properties.get('minimumTlsVersion')}.",
                {"accountName": storage_name, "minimumTlsVersion": properties.get("minimumTlsVersion")},
            )
        network_rules = properties.get("networkRuleSet", {})
        if isinstance(network_rules, dict) and str(network_rules.get("defaultAction", "")).lower() == "allow":
            add(
                "storage-network-default-allow",
                account_id,
                "Storage account network access should be restricted",
                "DefaultNetworkAccessAllowed",
                "The storage account network rules allow traffic by default.",
                {"accountName": storage_name, "defaultAction": network_rules.get("defaultAction")},
            )
        containers = data.get("containers", {})
        if isinstance(containers, dict):
            for container_name, container in containers.items():
                public_access = (
                    container.get("publicAccess", "none") if isinstance(container, dict) else str(container)
                )
                if str(public_access).lower() not in {"", "none", "off", "private"}:
                    add(
                        "storage-container-public-access",
                        f"{account_id}/blobServices/default/containers/{container_name}",
                        "Storage containers should not allow anonymous public access",
                        "PublicContainerAccessEnabled",
                        f"Container '{container_name}' allows anonymous public access.",
                        {
                            "accountName": storage_name,
                            "containerName": container_name,
                            "publicAccess": public_access,
                        },
                    )

    for vault_name, data in state.get("keyvaults", {}).items():
        if not isinstance(data, dict):
            continue
        vault = _format_keyvault(state, str(vault_name), data)
        properties = vault["properties"]
        network_acls = properties.get("networkAcls", {})
        if (
            properties.get("publicNetworkAccess") == "Enabled"
            and isinstance(network_acls, dict)
            and str(network_acls.get("defaultAction", "")).lower() == "allow"
        ):
            add(
                "keyvault-public-network-access",
                vault["id"],
                "Key Vaults should restrict public network access",
                "PublicNetworkAccessEnabled",
                "The key vault allows public network access and permits traffic by default.",
                {"vaultName": vault_name},
            )

    for key, data in state.get("nsg_rules", {}).items():
        if not isinstance(data, dict):
            continue
        parts = str(key).split("/")
        if len(parts) >= 3:
            rg, nsg_name, rule_name = parts[0], parts[1], parts[-1]
        else:
            rg, nsg_name, rule_name = _default_rg(state), str(key), str(data.get("name") or key)
        if (
            str(data.get("direction", "Inbound")).lower() == "inbound"
            and str(data.get("access", "Allow")).lower() == "allow"
            and str(data.get("sourceAddressPrefix", "*")) in {"*", "0.0.0.0/0", "Internet", "Any"}
            and str(data.get("destinationAddressPrefix", "*")) in {"*", "0.0.0.0/0", "Any"}
        ):
            rule_id = _resource_id(
                state, rg, f"Microsoft.Network/networkSecurityGroups/{nsg_name}/securityRules", rule_name
            )
            add(
                "nsg-wide-open-inbound",
                rule_id,
                "Network security group inbound rules should not allow unrestricted access",
                "AnySourceInboundAllow",
                f"NSG rule '{rule_name}' allows unrestricted inbound traffic.",
                {"networkSecurityGroup": nsg_name, "ruleName": rule_name},
            )

    for bucket, display in (("webapps", "App Service apps"), ("function_apps", "Function apps")):
        for app_name, data in state.get(bucket, {}).items():
            if not isinstance(data, dict):
                continue
            auth_settings = next(
                (
                    data[key]
                    for key in ("authSettings", "auth_settings", "siteAuthSettings", "site_auth_settings", "auth")
                    if isinstance(data.get(key), dict)
                ),
                {},
            )
            if not _as_bool(auth_settings.get("enabled", False)):
                app = _format_webapp(state, str(app_name), data)
                add(
                    f"{bucket}-authentication-disabled",
                    app["id"],
                    f"{display} should require App Service authentication when exposed publicly",
                    "AuthenticationDisabled",
                    f"Authentication is disabled for '{app_name}'.",
                    {"appName": app_name},
                )

    return findings


def _format_security_assessment(state: dict[str, Any], name: str, data: dict[str, Any]) -> dict[str, Any]:
    assessed_resource_id = data.get("assessedResourceId") or data.get("assessed_resource_id")
    assessment_id = data.get("id")
    if not assessment_id:
        scope = assessed_resource_id or _subscription_scope(state)
        assessment_id = f"{scope.rstrip('/')}/providers/Microsoft.Security/assessments/{name}"
    status_code = data.get("statusCode") or data.get("status_code") or data.get("status", "Healthy")
    if isinstance(status_code, dict):
        status = dict(status_code)
    else:
        status = {
            "code": status_code,
            "cause": data.get("statusCause") or data.get("status_cause"),
            "description": data.get("statusDescription") or data.get("status_description"),
        }
    properties = {
        "additionalData": data.get("additionalData") or data.get("additional_data"),
        "displayName": data.get("displayName") or data.get("display_name") or name,
        "resourceDetails": data.get("resourceDetails") or {"source": "Azure", "id": assessed_resource_id},
        "status": status,
    }
    return {
        "id": assessment_id,
        "name": data.get("name", name),
        "properties": properties,
        "type": "Microsoft.Security/assessments",
    }


def security_pricing_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    names = ["VirtualMachines", "StorageAccounts", "KeyVaults", "Containers", "AppServices"]
    pricing = state.get("security_pricing", {})
    return [_format_security_pricing(state, name, pricing.get(name, {"pricingTier": "Free"})) for name in names]


def security_pricing_show(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("name", "--name/-n")])
    return _format_security_pricing(
        state, args.name, state.get("security_pricing", {}).get(args.name, {"pricingTier": "Free"})
    )


def security_pricing_create(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("name", "--name/-n"), ("tier", "--tier")])
    state.setdefault("security_pricing", {})[args.name] = {
        "pricingTier": args.tier,
        "subPlan": getattr(args, "subplan", None),
    }
    return security_pricing_show(args, state, context)


def _format_security_pricing(state: dict[str, Any], name: str, data: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": f"/subscriptions/{_subscription_id(state)}/providers/Microsoft.Security/pricings/{name}",
        "name": name,
        "pricingTier": data.get("pricingTier", "Free"),
        "subPlan": data.get("subPlan"),
        "type": "Microsoft.Security/pricings",
    }


def lock_list(args: Any, state: dict[str, Any], context: BridgeContext) -> list[dict[str, Any]]:
    return state.get("locks", [])


def lock_create(args: Any, state: dict[str, Any], context: BridgeContext) -> dict[str, Any]:
    require_options(args, [("name", "--name/-n"), ("lock_type", "--lock-type")])
    record = {
        "id": f"/subscriptions/{_subscription_id(state)}/providers/Microsoft.Authorization/locks/{args.name}",
        "name": args.name,
        "level": args.lock_type,
        "notes": getattr(args, "notes", None),
    }
    state.setdefault("locks", []).append(record)
    return record


GROUP_DESCRIPTIONS = {
    "account": "Manage Azure subscription information.",
    "ad": "Manage Microsoft Entra ID entities.",
    "afd": "Manage Azure Front Door resources.",
    "aks": "Manage Azure Kubernetes Service clusters.",
    "cloud": "Manage registered Azure clouds.",
    "config": "Manage Azure CLI configuration.",
    "configure": "Manage Azure CLI defaults.",
    "eventgrid": "Manage Event Grid topics and subscriptions.",
    "functionapp": "Manage function apps.",
    "group": "Manage resource groups.",
    "keyvault": "Manage Key Vault resources.",
    "lock": "Manage Azure locks.",
    "login": "Log in to Azure.",
    "logout": "Log out from Azure.",
    "monitor": "Manage Azure Monitor resources.",
    "network": "Manage network resources.",
    "policy": "Manage policy resources.",
    "resource": "Manage Azure resources.",
    "rest": "Invoke a request against supported Azure REST endpoints.",
    "role": "Manage RBAC.",
    "security": "Manage Defender for Cloud settings.",
    "storage": "Manage storage resources.",
    "webapp": "Manage web apps.",
}


COMMANDS = {
    ("account", "show"): account_show,
    ("account", "list"): account_list,
    ("account", "set"): account_set,
    ("account", "clear"): account_clear,
    ("account", "get-access-token"): account_get_access_token,
    ("account", "list-locations"): account_list_locations,
    ("rest",): rest_command,
    ("login",): login,
    ("logout",): logout,
    ("configure",): configure,
    ("config", "set"): config_set,
    ("config", "get"): config_get,
    ("config", "param-persist", "on"): config_param_persist_on,
    ("config", "param-persist", "off"): config_param_persist_off,
    ("cloud", "show"): cloud_show,
    ("cloud", "list"): cloud_list,
    ("cloud", "set"): cloud_set,
    ("cloud", "register"): cloud_register_update,
    ("cloud", "update"): cloud_register_update,
    ("cloud", "unregister"): cloud_unregister,
    ("group", "list"): group_list,
    ("group", "show"): group_show,
    ("resource", "list"): resource_list,
    ("resource", "show"): resource_show,
    ("resource", "update"): resource_update,
    ("ad", "user", "list"): ad_user_list,
    ("ad", "user", "show"): ad_user_show,
    ("ad", "user", "update"): ad_user_update,
    ("ad", "user", "get-member-groups"): ad_user_get_member_groups,
    ("ad", "group", "list"): ad_group_list,
    ("ad", "group", "show"): ad_group_show,
    ("ad", "group", "get-member-groups"): ad_group_get_member_groups,
    ("ad", "group", "member", "list"): ad_group_member_list,
    ("ad", "sp", "list"): ad_sp_list,
    ("ad", "sp", "show"): ad_sp_show,
    ("ad", "sp", "update"): ad_sp_update,
    ("ad", "sp", "credential", "list"): ad_credential_list,
    ("ad", "sp", "credential", "reset"): ad_credential_reset,
    ("ad", "app", "list"): ad_app_list,
    ("ad", "app", "show"): ad_app_show,
    ("ad", "app", "credential", "list"): ad_credential_list,
    ("ad", "app", "credential", "delete"): ad_credential_delete,
    ("ad", "app", "credential", "reset"): ad_credential_reset,
    ("ad", "app", "permission", "list"): ad_permission_list,
    ("ad", "app", "permission", "add"): ad_permission_add,
    ("ad", "app", "permission", "delete"): ad_permission_delete,
    ("ad", "app", "federated-credential", "create"): ad_federated_credential_create,
    ("ad", "signed-in-user", "show"): ad_signed_in_user_show,
    ("role", "assignment", "list"): role_assignment_list,
    ("role", "assignment", "create"): role_assignment_create,
    ("role", "assignment", "delete"): role_assignment_delete,
    ("role", "definition", "list"): role_definition_list,
    ("keyvault", "list"): keyvault_list,
    ("keyvault", "show"): keyvault_show,
    ("keyvault", "update"): keyvault_update,
    ("keyvault", "key", "list"): keyvault_key_list,
    ("keyvault", "key", "show"): keyvault_key_show,
    ("keyvault", "certificate", "list"): keyvault_certificate_list,
    ("keyvault", "certificate", "show"): keyvault_certificate_show,
    ("keyvault", "secret", "list"): keyvault_secret_list,
    ("keyvault", "secret", "show"): keyvault_secret_show,
    ("keyvault", "secret", "set"): keyvault_secret_set,
    ("keyvault", "secret", "delete"): keyvault_secret_delete,
    ("keyvault", "set-policy"): keyvault_set_policy,
    ("keyvault", "delete-policy"): keyvault_delete_policy,
    ("keyvault", "network-rule", "list"): keyvault_network_rule_list,
    ("keyvault", "network-rule", "add"): keyvault_network_rule_add,
    ("keyvault", "network-rule", "remove"): keyvault_network_rule_remove,
    ("storage", "account", "list"): storage_account_list,
    ("storage", "account", "show"): storage_account_show,
    ("storage", "account", "update"): storage_account_update,
    ("storage", "account", "keys", "list"): storage_keys_list,
    ("storage", "account", "keys", "renew"): storage_keys_renew,
    ("storage", "container", "list"): storage_container_list,
    ("storage", "container", "set-permission"): storage_container_set_permission,
    ("storage", "blob", "list"): storage_blob_list,
    ("storage", "blob", "show"): storage_blob_show,
    ("storage", "blob", "download"): storage_blob_download,
    ("storage", "blob", "upload"): storage_blob_upload,
    ("network", "nsg", "list"): nsg_list,
    ("network", "nsg", "show"): nsg_show,
    ("network", "nsg", "create"): nsg_create,
    ("network", "nsg", "rule", "list"): nsg_rule_list,
    ("network", "nsg", "rule", "show"): nsg_rule_show,
    ("network", "nsg", "rule", "create"): nsg_rule_create,
    ("network", "nsg", "rule", "update"): nsg_rule_update,
    ("network", "nsg", "rule", "delete"): nsg_rule_delete,
    ("network", "vnet", "list"): vnet_list,
    ("network", "vnet", "show"): vnet_show,
    ("network", "vnet", "subnet", "list"): subnet_list,
    ("network", "vnet", "subnet", "show"): subnet_show,
    ("network", "vnet", "subnet", "create"): subnet_create,
    ("network", "private-endpoint", "list"): private_endpoint_list,
    ("network", "private-endpoint", "show"): private_endpoint_show,
    ("network", "private-endpoint", "create"): private_endpoint_create,
    ("network", "private-dns", "zone", "create"): private_dns_zone_create,
    ("network", "private-dns", "link", "vnet", "create"): private_dns_link_create,
    ("webapp", "list"): webapp_list,
    ("webapp", "show"): webapp_show,
    ("webapp", "auth", "show"): webapp_auth_show,
    ("webapp", "config", "show"): webapp_config_show,
    ("webapp", "config", "set"): webapp_config_set,
    ("webapp", "identity", "show"): webapp_identity_show,
    ("webapp", "config", "appsettings", "list"): appsettings_list,
    ("webapp", "config", "appsettings", "set"): appsettings_set,
    ("webapp", "deployment", "slot", "swap"): slot_swap,
    ("functionapp", "list"): functionapp_list,
    ("functionapp", "show"): functionapp_show,
    ("functionapp", "auth", "show"): functionapp_auth_show,
    ("functionapp", "config", "show"): functionapp_config_show,
    ("functionapp", "config", "appsettings", "list"): appsettings_list,
    ("functionapp", "config", "appsettings", "set"): functionapp_appsettings_set,
    ("functionapp", "identity", "show"): functionapp_identity_show,
    ("functionapp", "function", "list"): functionapp_function_list,
    ("eventgrid", "topic", "list"): eventgrid_topic_list,
    ("eventgrid", "topic", "show"): eventgrid_topic_show,
    ("eventgrid", "event-subscription", "list"): eventgrid_subscription_list,
    ("eventgrid", "event-subscription", "create"): eventgrid_subscription_create,
    ("eventgrid", "event-subscription", "delete"): eventgrid_subscription_delete,
    ("afd", "profile", "list"): afd_profile_list,
    ("afd", "profile", "show"): afd_profile_show,
    ("afd", "endpoint", "list"): afd_endpoint_list,
    ("afd", "waf-policy", "list"): waf_policy_list,
    ("aks", "list"): aks_list,
    ("aks", "show"): aks_show,
    ("aks", "get-credentials"): aks_get_credentials,
    ("aks", "command", "invoke"): aks_command_invoke,
    ("monitor", "diagnostic-settings", "list"): empty_list,
    ("monitor", "diagnostic-settings", "subscription", "list"): monitor_diagnostic_settings_subscription_list,
    ("monitor", "diagnostic-settings", "subscription", "show"): monitor_diagnostic_settings_subscription_show,
    ("monitor", "diagnostic-settings", "subscription", "create"): monitor_diagnostic_settings_subscription_create,
    ("monitor", "diagnostic-settings", "subscription", "delete"): monitor_diagnostic_settings_subscription_delete,
    ("monitor", "log-analytics", "workspace", "list"): empty_list,
    ("policy", "assignment", "list"): empty_list,
    ("policy", "definition", "list"): empty_list,
    ("security", "assessment", "list"): security_assessment_list,
    ("security", "assessment", "show"): security_assessment_show,
    ("security", "assessment", "create"): security_assessment_create,
    ("security", "assessment", "delete"): security_assessment_delete,
    ("security", "pricing", "list"): security_pricing_list,
    ("security", "pricing", "show"): security_pricing_show,
    ("security", "pricing", "create"): security_pricing_create,
    ("lock", "list"): lock_list,
    ("lock", "create"): lock_create,
}
