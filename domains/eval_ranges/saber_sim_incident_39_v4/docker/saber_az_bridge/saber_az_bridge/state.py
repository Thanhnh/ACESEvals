"""State loading and normalization for SABER Az Bridge."""

from __future__ import annotations

import json
import os
import tempfile
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - Linux containers have fcntl.
    fcntl = None

try:
    import yaml
except ImportError:  # pragma: no cover - depends on container image.
    yaml = None

DEFAULT_SUBSCRIPTION_ID = "12345678-1234-1234-1234-123456789abc"
DEFAULT_TENANT_ID = "87654321-4321-4321-4321-cba987654321"
DEFAULT_SUBSCRIPTION_NAME = "SABER-Sim Subscription"
DEFAULT_LOCATION = "eastus"
DEFAULT_RESOURCE_GROUP = "production-rg"


def now_iso() -> str:
    """Return current UTC timestamp in Azure-friendly format."""

    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path: Path | None) -> dict[str, Any]:
    """Load a JSON object from path, returning an empty object when absent."""

    if path is None or not path.exists():
        return {}
    data = json.loads(path.read_text())
    return data if isinstance(data, dict) else {}


def load_yaml(path: Path | None) -> dict[str, Any]:
    """Load a YAML object from path, returning an empty object when absent."""

    if path is None or not path.exists():
        return {}
    if yaml is None:
        raise RuntimeError("YAML state loading requires the 'PyYAML' Python package.")
    data = yaml.safe_load(path.read_text()) or {}
    return data if isinstance(data, dict) else {}


def default_state() -> dict[str, Any]:
    """Return an empty canonical bridge state."""

    return {
        "subscription": {
            "id": DEFAULT_SUBSCRIPTION_ID,
            "tenantId": DEFAULT_TENANT_ID,
            "name": DEFAULT_SUBSCRIPTION_NAME,
            "location": DEFAULT_LOCATION,
        },
        "tenants": {},
        "resource_groups": {},
        "storage_accounts": {},
        "keyvaults": {},
        "secrets": {},
        "keyvault_keys": {},
        "keyvault_certificates": {},
        "ad_users": {},
        "ad_groups": {},
        "directory_roles": {},
        "service_principals": {},
        "ad_applications": {},
        "app_credentials": {},
        "ad_app_permissions": {},
        "ad_federated_credentials": {},
        "role_assignments": [],
        "nsgs": {},
        "nsg_rules": {},
        "vnets": {},
        "subnets": {},
        "private_endpoints": {},
        "private_dns_zones": {},
        "private_dns_links": {},
        "webapps": {},
        "function_apps": {},
        "managed_identities": {},
        "event_grid_topics": {},
        "event_grid_subscriptions": {},
        "front_door_profiles": {},
        "waf_policies": {},
        "aks_clusters": {},
        "locks": [],
        "security_assessments": {},
        "security_pricing": {},
        "monitoring": {},
        "config": {"defaults": {}, "cloud": "AzureCloud"},
        "sessions": {},
    }


def normalize_state(
    raw_state: dict[str, Any] | None, base_infrastructure: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Normalize generated SABER state and infrastructure into a canonical schema."""

    raw = deepcopy(raw_state or {})
    base = deepcopy(base_infrastructure or {})
    state = default_state()
    _merge_subscription(state, raw, base)
    _merge_resource_groups(state, raw, base)
    _merge_storage_accounts(state, raw, base)
    _merge_keyvaults_and_secrets(state, raw, base)
    _merge_identities(state, raw, base)
    _merge_directory_objects(state, raw)
    _merge_role_assignments(state, raw)
    _merge_network(state, raw)
    _merge_web_and_functions(state, raw, base)
    _merge_managed_identities(state, raw, base)
    _merge_event_grid(state, raw, base)
    _merge_front_door(state, raw, base)
    _copy_simple_categories(state, raw)
    _infer_resource_groups_from_resources(state)
    return state


def _merge_subscription(state: dict[str, Any], raw: dict[str, Any], base: dict[str, Any]) -> None:
    sub = base.get("subscription") if isinstance(base.get("subscription"), dict) else {}
    raw_sub = raw.get("subscription") if isinstance(raw.get("subscription"), dict) else {}
    subscription = state["subscription"]
    subscription["id"] = str(raw_sub.get("id") or sub.get("id") or DEFAULT_SUBSCRIPTION_ID)
    subscription["tenantId"] = str(
        raw_sub.get("tenantId")
        or raw_sub.get("tenant_id")
        or sub.get("tenant_id")
        or sub.get("tenantId")
        or DEFAULT_TENANT_ID
    )
    subscription["name"] = str(raw_sub.get("name") or sub.get("name") or DEFAULT_SUBSCRIPTION_NAME)
    subscription["location"] = str(raw_sub.get("location") or sub.get("location") or DEFAULT_LOCATION)
    state["tenants"][subscription["tenantId"]] = {
        "tenantId": subscription["tenantId"],
        "displayName": base.get("tenant_display_name", "SABER-Sim Tenant"),
    }


def _merge_resource_groups(state: dict[str, Any], raw: dict[str, Any], base: dict[str, Any]) -> None:
    groups: dict[str, Any] = {}
    raw_groups = raw.get("resource_groups")
    if isinstance(raw_groups, dict):
        for name, data in raw_groups.items():
            groups[str(name)] = dict(data or {}) if isinstance(data, dict) else {}
    elif isinstance(raw_groups, list):
        for item in raw_groups:
            if isinstance(item, dict) and item.get("name"):
                groups[str(item["name"])] = dict(item)
    base_groups = base.get("resource_groups")
    if isinstance(base_groups, list):
        for item in base_groups:
            if isinstance(item, dict) and item.get("name"):
                groups.setdefault(str(item["name"]), {}).update(item)
    if not groups:
        groups[DEFAULT_RESOURCE_GROUP] = {"name": DEFAULT_RESOURCE_GROUP, "location": state["subscription"]["location"]}
    for name, data in groups.items():
        state["resource_groups"][name] = {
            "name": name,
            "location": data.get("location", state["subscription"]["location"]),
            "tags": data.get("tags", {}),
        }


def _first_resource_group(state: dict[str, Any]) -> str:
    if state["resource_groups"]:
        return next(iter(state["resource_groups"]))
    return DEFAULT_RESOURCE_GROUP


def _merge_storage_accounts(state: dict[str, Any], raw: dict[str, Any], base: dict[str, Any]) -> None:
    accounts = raw.get("storage_accounts")
    if isinstance(accounts, dict):
        for name, data in accounts.items():
            state["storage_accounts"][str(name)] = dict(data or {}) if isinstance(data, dict) else {}
    base_accounts = base.get("storage_accounts")
    if isinstance(base_accounts, list):
        for item in base_accounts:
            if not isinstance(item, dict) or not item.get("name"):
                continue
            name = str(item["name"])
            account = state["storage_accounts"].setdefault(name, {})
            account.setdefault("resourceGroup", item.get("resource_group", _first_resource_group(state)))
            account.setdefault("location", item.get("location", state["subscription"]["location"]))
            account.setdefault("kind", item.get("kind", "StorageV2"))
            account.setdefault("sku", item.get("sku", "Standard_LRS"))
            if item.get("keys") and "keys" not in account:
                account["keys"] = [
                    {
                        "keyName": key.get("name", f"key{index + 1}"),
                        "value": key.get("value", ""),
                        "permissions": "FULL",
                    }
                    for index, key in enumerate(item.get("keys", []))
                    if isinstance(key, dict)
                ]
            containers = account.setdefault("containers", {})
            for container in item.get("benign_containers", []) or []:
                if not isinstance(container, dict) or not container.get("name"):
                    continue
                cname = str(container["name"])
                cdata = containers.setdefault(cname, {})
                cdata.setdefault("publicAccess", "container" if container.get("public") else "none")
                files = cdata.setdefault("files", {})
                for file_item in container.get("files", []) or []:
                    if isinstance(file_item, dict) and file_item.get("name"):
                        files[str(file_item["name"])] = file_item.get("content", "")


def _merge_keyvaults_and_secrets(state: dict[str, Any], raw: dict[str, Any], base: dict[str, Any]) -> None:
    raw_keyvaults = raw.get("keyvaults")
    keyvault_items = raw_keyvaults.items() if isinstance(raw_keyvaults, dict) else []
    for name, data in keyvault_items:
        state["keyvaults"][str(name)] = dict(data or {}) if isinstance(data, dict) else {}
        if isinstance(data, dict):
            _merge_keyvault_object_collection(state["keyvault_keys"], str(name), data.get("keys"))
            _merge_keyvault_object_collection(state["keyvault_certificates"], str(name), data.get("certificates"))
    raw_secrets = raw.get("secrets")
    if isinstance(raw_secrets, dict):
        state["secrets"] = deepcopy(raw_secrets)
    raw_keys = raw.get("keyvault_keys")
    if isinstance(raw_keys, dict):
        for vault_name, objects in raw_keys.items():
            _merge_keyvault_object_collection(state["keyvault_keys"], str(vault_name), objects)
    raw_certificates = raw.get("keyvault_certificates")
    if isinstance(raw_certificates, dict):
        for vault_name, objects in raw_certificates.items():
            _merge_keyvault_object_collection(state["keyvault_certificates"], str(vault_name), objects)
    base_vaults = base.get("key_vaults")
    if isinstance(base_vaults, list):
        for item in base_vaults:
            if not isinstance(item, dict) or not item.get("name"):
                continue
            name = str(item["name"])
            vault = state["keyvaults"].setdefault(name, {})
            vault.setdefault("resourceGroup", item.get("resource_group", _first_resource_group(state)))
            vault.setdefault("location", item.get("location", state["subscription"]["location"]))
            vault.setdefault(
                "properties",
                {
                    "tenantId": state["subscription"]["tenantId"],
                    "sku": {"family": "A", "name": item.get("sku", "standard")},
                    "publicNetworkAccess": "Enabled",
                    "networkAcls": {
                        "bypass": "AzureServices",
                        "defaultAction": "Allow",
                        "ipRules": [],
                        "virtualNetworkRules": [],
                    },
                    "accessPolicies": [],
                },
            )
            vault_secrets = state["secrets"].setdefault(name, {})
            for secret in item.get("benign_secrets", []) or []:
                if isinstance(secret, dict) and secret.get("name"):
                    vault_secrets.setdefault(
                        str(secret["name"]),
                        {
                            "value": secret.get("value", ""),
                            "version": "v1",
                            "attributes": {"enabled": True, "created": now_iso(), "updated": now_iso()},
                        },
                    )
            _merge_keyvault_object_collection(state["keyvault_keys"], name, item.get("keys"))
            _merge_keyvault_object_collection(state["keyvault_certificates"], name, item.get("certificates"))


def _merge_keyvault_object_collection(target: dict[str, Any], vault_name: str, source: Any) -> None:
    if isinstance(source, dict):
        target.setdefault(vault_name, {}).update(deepcopy(source))
        return
    if isinstance(source, list):
        vault_objects = target.setdefault(vault_name, {})
        for item in source:
            if isinstance(item, dict) and item.get("name"):
                vault_objects.setdefault(str(item["name"]), deepcopy(item))


def _merge_identities(state: dict[str, Any], raw: dict[str, Any], base: dict[str, Any]) -> None:
    for key in (
        "service_principals",
        "app_credentials",
        "ad_app_permissions",
        "ad_federated_credentials",
        "ad_applications",
    ):
        value = raw.get(key)
        if isinstance(value, dict):
            state[key] = deepcopy(value)
    exchange = base.get("exchange_service_principal")
    if isinstance(exchange, dict) and exchange.get("app_id"):
        app_id = str(exchange["app_id"])
        display = str(exchange.get("display_name") or exchange.get("name") or app_id)
        state["service_principals"].setdefault(
            display.lower().replace(" ", "-"),
            {
                "appId": app_id,
                "objectId": str(uuid.uuid5(uuid.NAMESPACE_URL, app_id)),
                "displayName": display,
                "description": exchange.get("description"),
                "accountEnabled": True,
                "servicePrincipalType": "Application",
                "passwordCredentials": [],
                "keyCredentials": [],
            },
        )
    for sp in base.get("benign_service_principals", []) or []:
        if isinstance(sp, dict) and sp.get("app_id"):
            app_id = str(sp["app_id"])
            name = str(sp.get("name") or app_id)
            state["service_principals"].setdefault(
                name,
                {
                    "appId": app_id,
                    "objectId": str(uuid.uuid5(uuid.NAMESPACE_URL, app_id)),
                    "displayName": name,
                    "description": sp.get("description"),
                    "accountEnabled": True,
                    "servicePrincipalType": "Application",
                    "passwordCredentials": [],
                    "keyCredentials": [],
                },
            )


def _merge_directory_objects(state: dict[str, Any], raw: dict[str, Any]) -> None:
    _merge_named_records(
        state["ad_users"],
        raw.get("ad_users") or raw.get("users"),
        ("id", "objectId", "object_id", "userPrincipalName", "upn", "username"),
    )
    _merge_named_records(
        state["ad_groups"],
        raw.get("ad_groups") or raw.get("groups"),
        ("id", "objectId", "object_id", "displayName", "display_name", "mailNickname", "name"),
    )
    _merge_named_records(
        state["directory_roles"],
        raw.get("directory_roles") or raw.get("directoryRoles"),
        ("id", "roleTemplateId", "displayName", "display_name", "name"),
    )


def _merge_role_assignments(state: dict[str, Any], raw: dict[str, Any]) -> None:
    assignments = raw.get("role_assignments")
    normalized: list[dict[str, Any]] = []
    if isinstance(assignments, list):
        iterable = enumerate(assignments)
    elif isinstance(assignments, dict):
        iterable = assignments.items()
    else:
        iterable = []
    for key, value in iterable:
        if isinstance(value, list):
            for index, item in enumerate(value):
                if isinstance(item, dict):
                    normalized.append(_role_assignment_record(f"{key}-{index}", item, principal_id=str(key)))
        elif isinstance(value, dict):
            normalized.append(_role_assignment_record(str(key), value))
    state["role_assignments"] = normalized


def _role_assignment_record(name: str, data: dict[str, Any], principal_id: str | None = None) -> dict[str, Any]:
    return {
        "name": data.get("name", name),
        "id": data.get("id"),
        "principalId": data.get("principalId", principal_id or data.get("assignee", "")),
        "principalType": data.get("principalType", "ServicePrincipal"),
        "roleDefinitionName": data.get("roleDefinitionName") or data.get("role", "Reader"),
        "scope": data.get("scope", f"/subscriptions/{DEFAULT_SUBSCRIPTION_ID}"),
        "createdOn": data.get("createdOn", now_iso()),
    }


def _merge_network(state: dict[str, Any], raw: dict[str, Any]) -> None:
    raw_nsgs = raw.get("nsgs")
    if isinstance(raw_nsgs, dict):
        state["nsgs"] = deepcopy(raw_nsgs)
    raw_rules = raw.get("nsg_rules")
    if isinstance(raw_rules, dict):
        for key, value in raw_rules.items():
            if isinstance(value, dict) and isinstance(value.get("rules"), list):
                rg = value.get("resourceGroup", DEFAULT_RESOURCE_GROUP)
                nsg_name = str(value.get("name", key))
                state["nsgs"].setdefault(f"{rg}/{nsg_name}", {"name": nsg_name, "resourceGroup": rg})
                for rule in value["rules"]:
                    if isinstance(rule, dict) and rule.get("name"):
                        _add_nsg_rule(state, rg, nsg_name, rule)
            elif isinstance(value, dict):
                parts = str(key).split("/")
                if len(parts) >= 3:
                    state["nsg_rules"][key] = deepcopy(value)
                else:
                    _add_nsg_rule(state, DEFAULT_RESOURCE_GROUP, str(key), value)
    for key in ("vnets", "subnets", "private_endpoints", "private_dns_zones", "private_dns_links"):
        value = raw.get(key)
        if isinstance(value, dict):
            state[key] = deepcopy(value)


def _add_nsg_rule(state: dict[str, Any], resource_group: str, nsg_name: str, rule: dict[str, Any]) -> None:
    rule_name = str(rule["name"])
    record = deepcopy(rule)
    record.setdefault("resourceGroup", resource_group)
    record.setdefault("nsgName", nsg_name)
    state["nsg_rules"][f"{resource_group}/{nsg_name}/{rule_name}"] = record


def _merge_web_and_functions(state: dict[str, Any], raw: dict[str, Any], base: dict[str, Any]) -> None:
    if isinstance(raw.get("webapps"), dict):
        state["webapps"] = deepcopy(raw["webapps"])
    if isinstance(raw.get("function_apps"), dict):
        state["function_apps"] = deepcopy(raw["function_apps"])
    for key, target, kind in (("app_services", "webapps", "app"), ("function_apps", "function_apps", "functionapp")):
        items = base.get(key)
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict) and item.get("name"):
                name = str(item["name"])
                state[target].setdefault(
                    name,
                    {
                        "name": name,
                        "resourceGroup": item.get("resource_group", _first_resource_group(state)),
                        "location": item.get("location", state["subscription"]["location"]),
                        "kind": kind,
                        "state": "Running",
                        "appSettings": {},
                    },
                )


def _merge_managed_identities(state: dict[str, Any], raw: dict[str, Any], base: dict[str, Any]) -> None:
    _merge_named_records(
        state["managed_identities"],
        raw.get("managed_identities") or raw.get("managedIdentities"),
        ("id", "name", "principalId", "principal_id"),
    )
    _merge_named_records(
        state["managed_identities"],
        base.get("managed_identities") or base.get("managedIdentities"),
        ("id", "name", "principalId", "principal_id"),
    )
    _attach_managed_identities(state, "webapps", ("webapp", "appservice", "app-service"))
    _attach_managed_identities(state, "function_apps", ("function", "functionapp"))


def _merge_named_records(
    target: dict[str, Any],
    source: Any,
    key_fields: tuple[str, ...],
) -> None:
    if isinstance(source, dict):
        for key, value in source.items():
            if not isinstance(value, dict):
                continue
            record = deepcopy(value)
            record.setdefault("name", str(key))
            target[str(key)] = record
        return
    if not isinstance(source, list):
        return
    for item in source:
        if not isinstance(item, dict):
            continue
        key = next((str(item[field]) for field in key_fields if item.get(field) not in (None, "")), None)
        if key:
            target[key] = deepcopy(item)


def _attach_managed_identities(state: dict[str, Any], bucket: str, keywords: tuple[str, ...]) -> None:
    identities = state.get("managed_identities", {})
    if not isinstance(identities, dict) or not identities:
        return
    for site_name, site in state.get(bucket, {}).items():
        if not isinstance(site, dict) or isinstance(site.get("identity"), dict):
            continue
        identity = _identity_for_site(str(site_name), identities, keywords)
        if identity is not None:
            site["identity"] = {
                "principalId": identity.get("principalId") or identity.get("principal_id"),
                "tenantId": identity.get("tenantId") or state["subscription"]["tenantId"],
                "type": identity.get("type", "SystemAssigned"),
                "userAssignedIdentities": identity.get("userAssignedIdentities"),
            }


def _identity_for_site(
    site_name: str,
    identities: dict[str, Any],
    keywords: tuple[str, ...],
) -> dict[str, Any] | None:
    typed_matches: list[dict[str, Any]] = []
    untyped_matches: list[dict[str, Any]] = []
    for key, value in identities.items():
        if not isinstance(value, dict):
            continue
        search_values = " ".join(
            str(value.get(field, "")) for field in ("name", "target", "site", "app", "resourceName", "resource_name")
        )
        search_values = f"{key} {search_values}".lower()
        if site_name.lower() in search_values:
            return value
        if any(keyword in search_values for keyword in keywords):
            typed_matches.append(value)
        else:
            untyped_matches.append(value)
    if len(typed_matches) == 1:
        return typed_matches[0]
    if len(identities) == 1 and untyped_matches:
        return untyped_matches[0]
    return None


def _merge_event_grid(state: dict[str, Any], raw: dict[str, Any], base: dict[str, Any]) -> None:
    for key in ("event_grid_topics", "event_grid_subscriptions"):
        if isinstance(raw.get(key), dict):
            state[key] = deepcopy(raw[key])
    topics = base.get("event_grid_topics")
    if isinstance(topics, list):
        for item in topics:
            if isinstance(item, dict) and item.get("name"):
                name = str(item["name"])
                state["event_grid_topics"].setdefault(
                    name,
                    {
                        "name": name,
                        "resourceGroup": item.get("resource_group", _first_resource_group(state)),
                        "location": item.get("location", state["subscription"]["location"]),
                    },
                )


def _merge_front_door(state: dict[str, Any], raw: dict[str, Any], base: dict[str, Any]) -> None:
    for key in ("front_door_profiles", "waf_policies"):
        if isinstance(raw.get(key), dict):
            state[key] = deepcopy(raw[key])
    if base.get("front_door") and isinstance(base["front_door"], dict):
        data = base["front_door"]
        name = str(data.get("name", "prod-frontdoor"))
        state["front_door_profiles"].setdefault(
            name,
            {
                "name": name,
                "resourceGroup": data.get("resource_group", _first_resource_group(state)),
                "location": data.get("location", "Global"),
                "endpoints": data.get("endpoints", []),
            },
        )


def _copy_simple_categories(state: dict[str, Any], raw: dict[str, Any]) -> None:
    for key in ("aks_clusters", "locks", "security_assessments", "security_pricing", "monitoring"):
        value = raw.get(key)
        if isinstance(value, (dict, list)):
            state[key] = deepcopy(value)


_RESOURCE_GROUP_RESOURCE_BUCKETS = (
    "storage_accounts",
    "keyvaults",
    "nsgs",
    "vnets",
    "private_endpoints",
    "private_dns_zones",
    "private_dns_links",
    "webapps",
    "function_apps",
    "managed_identities",
    "event_grid_topics",
    "front_door_profiles",
    "waf_policies",
    "aks_clusters",
)


def _infer_resource_groups_from_resources(state: dict[str, Any]) -> None:
    """Ensure ARM resource groups referenced by state resources are discoverable."""

    groups = state.setdefault("resource_groups", {})
    location_default = state.get("subscription", {}).get("location", DEFAULT_LOCATION)

    def add_group(name: Any, location: Any = None) -> None:
        group_name = str(name or "").strip()
        if not group_name:
            return
        group = groups.setdefault(group_name, {"name": group_name, "location": location or location_default, "tags": {}})
        group.setdefault("name", group_name)
        if location and not group.get("location"):
            group["location"] = location
        group.setdefault("location", location_default)
        group.setdefault("tags", {})

    for bucket in _RESOURCE_GROUP_RESOURCE_BUCKETS:
        items = state.get(bucket)
        if isinstance(items, dict):
            for key, data in items.items():
                if not isinstance(data, dict):
                    continue
                group_name = (
                    data.get("resourceGroup")
                    or data.get("resource_group")
                    or _resource_group_from_id(data.get("id"))
                    or _resource_group_from_key(str(key))
                )
                add_group(group_name, data.get("location"))
        elif isinstance(items, list):
            for data in items:
                if not isinstance(data, dict):
                    continue
                group_name = (
                    data.get("resourceGroup") or data.get("resource_group") or _resource_group_from_id(data.get("id"))
                )
                add_group(group_name, data.get("location"))

    for assignment in state.get("role_assignments", []) or []:
        if isinstance(assignment, dict):
            add_group(_resource_group_from_id(assignment.get("scope")))


def _resource_group_from_key(key: str) -> str | None:
    if "/" not in key:
        return None
    candidate = key.split("/", 1)[0].strip()
    return candidate or None


def _resource_group_from_id(resource_id: Any) -> str | None:
    if not resource_id:
        return None
    parts = str(resource_id).strip("/").split("/")
    lowered = [part.lower() for part in parts]
    if "resourcegroups" not in lowered:
        return None
    index = lowered.index("resourcegroups")
    if index + 1 >= len(parts):
        return None
    return parts[index + 1]


class StateStore:
    """Manage bridge state files."""

    def __init__(self, state_path: Path, initial_path: Path | None, base_path: Path | None) -> None:
        self.state_path = state_path
        self.initial_path = initial_path
        self.base_path = base_path
        self.lock_path = state_path.with_suffix(state_path.suffix + ".lock")

    @contextmanager
    def locked(self) -> Iterator[dict[str, Any]]:
        """Yield mutable state under an exclusive file lock and persist on exit."""

        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            state = self.load()
            yield state
            self.save(state)
        finally:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def load(self) -> dict[str, Any]:
        """Load canonical state, initializing it if necessary."""

        if self.state_path.exists():
            saved = load_json(self.state_path)
            state = normalize_state(saved, {})
            for key in ("config", "sessions"):
                if isinstance(saved.get(key), dict):
                    state[key] = saved[key]
            return state
        raw = load_json(self.initial_path)
        base = load_yaml(self.base_path)
        return normalize_state(raw, base)

    def save(self, state: dict[str, Any]) -> None:
        """Atomically write state."""

        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.state_path.parent, suffix=".json")
        try:
            with os.fdopen(fd, "w") as handle:
                json.dump(state, handle, indent=2)
            os.replace(tmp, self.state_path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
