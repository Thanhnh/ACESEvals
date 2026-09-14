"""Sentinel -> Defender XDR Advanced Hunting telemetry translation (dual-emit).

The attack already emits **Sentinel** telemetry (SigninLogs, OfficeActivity,
AuditLogs, …). SIEM-querying agents built against **Defender XDR Advanced
Hunting** query a different table universe (AADSignInEventsBeta, EmailEvents,
UrlClickEvents, CloudAppEvents, …). This module RESHAPES the Sentinel rows we
already produce into the AH schema so the **same events** also land in the AH
tables — closing the "Defender surface" half of the "Sentinel AND Defender"
acceptance bar without a second emission path in every mock.

Design (Phase 10 §3b-F, adapted for saber_sim):
  * RENAME — same data, different column (TimeGenerated->Timestamp, UPN->AccountUpn)
  * SYNTH  — AH-only fields with no Sentinel source, derived from context
  * Routing is **operation-aware** for OfficeActivity, so each technique lands in
    its faithful AH table:
      - Send             -> EmailEvents      (internal spearphishing, T1534: an email WAS sent)
      - New-InboxRule    -> CloudAppEvents   (mailbox-rule config change, T1564.008; ActionType mirrors the op)
      - MailItemsAccessed-> CloudAppEvents   (mailbox access = exfil, T1114.002)
  * Sign-ins -> AADSignInEventsBeta (the faithful Defender artifact for both the
    device-code phishing sign-in T1566.002 and the valid-account sign-in T1078.004).

The ``AttackTechnique`` capture tag (Phase 10 §6) is PRESERVED onto every
translated row so the corpus snapshot identifies the AH rows as attack telemetry,
exactly as on the Sentinel side. This module never authenticates or alters mock
behaviour — it only reshapes already-ingested records.

Pure functions — unit tested in tests/test_xdr_translate.py.
"""

from __future__ import annotations

import re
from typing import Any

ATTACK_TAG_FIELD = "AttackTechnique"

_PHISH_OPS = ("MailItemsAccessed", "Send", "MessageRead", "UrlClick",
              "TIUrlClickData", "Click")


def _get(rec: dict[str, Any], *keys: str, default: Any = None) -> Any:
    """First present, non-None value among keys (supports nested ``properties.x``)."""
    for k in keys:
        if "." in k:
            cur: Any = rec
            for part in k.split("."):
                cur = cur.get(part) if isinstance(cur, dict) else None
            if cur is not None:
                return cur
        elif rec.get(k) is not None:
            return rec[k]
    return default


def _operation(rec: dict[str, Any]) -> str:
    return str(_get(rec, "Operation", "operationName", "OperationName", default=""))


# ── Translators ──────────────────────────────────────────────────────────────


def to_aad_signin_beta(rec: dict[str, Any]) -> dict[str, Any] | None:
    """SigninLogs / AADSignInLogs -> AADSignInEventsBeta (XDR identity sign-in)."""
    ts = _get(rec, "Timestamp", "TimeGenerated", "time", "CreationTime")
    if ts is None:
        return None
    return {
        "Timestamp": ts,
        "AccountUpn": _get(rec, "AccountUpn", "UserPrincipalName", "properties.userPrincipalName", "Identity"),
        "AccountObjectId": _get(rec, "AccountObjectId", "UserId", "properties.userId"),
        "AccountDisplayName": _get(rec, "UserDisplayName", "properties.userDisplayName"),
        "IPAddress": _get(rec, "IPAddress", "callerIpAddress", "properties.ipAddress"),
        "Application": _get(rec, "Application", "AppDisplayName", "properties.appDisplayName"),
        "ApplicationId": _get(rec, "ApplicationId", "AppId", "properties.appId"),
        "ResourceDisplayName": _get(rec, "ResourceDisplayName", "properties.resourceDisplayName"),
        "ErrorCode": _coerce_int(_get(rec, "ErrorCode", "ResultType", "properties.status.errorCode", default=0)),
        "RiskLevelDuringSignIn": _get(rec, "RiskLevelDuringSignIn", "RiskLevelAggregated", default="none"),
        "ConditionalAccessStatus": _get(rec, "ConditionalAccessStatus", default="notApplied"),
        "AuthenticationRequirement": _get(rec, "AuthenticationRequirement", default="singleFactorAuthentication"),
        "ClientAppUsed": _get(rec, "ClientAppUsed", "ClientApp", default=""),
        "Country": _get(rec, "Country", "Location", default=""),
        "ReportId": str(_get(rec, "ReportId", "Id", "correlationId", default=_hashish(rec))),
        "_source": "AADSignInEventsBeta",
    }


def to_email_events(rec: dict[str, Any]) -> dict[str, Any] | None:
    """Office/Exchange audit -> EmailEvents.

    Faithful for an email that was SENT/DELIVERED — internal spearphishing
    (T1534, OfficeActivity ``Send``) or a delivered phishing lure. The sender is
    the (compromised) mailbox for an internal send.
    """
    ts = _get(rec, "Timestamp", "TimeGenerated", "CreationTime", "time")
    if ts is None:
        return None
    op = _operation(rec)
    sender = _get(rec, "SenderFromAddress", "SenderAddress", "Sender",
                  "MailboxOwnerUPN", "UserId", default="unknown@external.com")
    direction = "Intraorg" if op == "Send" else "Inbound"
    return {
        "Timestamp": ts,
        "NetworkMessageId": str(_get(rec, "NetworkMessageId", "InternetMessageId", "Id", default=_hashish(rec))),
        "SenderFromAddress": sender,
        "SenderDisplayName": _get(rec, "SenderDisplayName", default=""),
        "RecipientEmailAddress": _get(rec, "RecipientEmailAddress", "MailboxOwnerUPN", "UserId", default=""),
        "Subject": _get(rec, "Subject", default=""),
        "EmailDirection": direction,
        "DeliveryAction": _get(rec, "DeliveryAction", default="Delivered"),
        "ThreatTypes": "Phish",  # SYNTH — phishing context, no Sentinel source
        "_source": "EmailEvents",
    }


def to_url_click_events(rec: dict[str, Any]) -> dict[str, Any] | None:
    """Office/Exchange audit -> UrlClickEvents (only when a real URL is present)."""
    url = _get(rec, "Url", "URL", "ObjectId", "MessageUrl")
    if url is None or not re.search(r"https?://|\.[a-z]{2,}", str(url)):
        return None  # no real URL to model a click on
    ts = _get(rec, "Timestamp", "TimeGenerated", "CreationTime", "time")
    if ts is None:
        return None
    return {
        "Timestamp": ts,
        "Url": url,
        "UrlChain": [url],  # SYNTH — single hop
        "NetworkMessageId": str(_get(rec, "NetworkMessageId", "InternetMessageId", "Id", default=_hashish(rec))),
        "AccountUpn": _get(rec, "AccountUpn", "MailboxOwnerUPN", "UserId"),
        "RecipientEmailAddress": _get(rec, "RecipientEmailAddress", "MailboxOwnerUPN", "UserId"),
        "ActionType": "ClickAllowed",   # SYNTH
        "IsClickedThrough": True,        # SYNTH
        "ThreatTypes": "Phish",         # SYNTH
        "_source": "UrlClickEvents",
    }


def to_cloud_app_events(rec: dict[str, Any]) -> dict[str, Any] | None:
    """Office/Exchange audit -> CloudAppEvents (cloud-app activity).

    Faithful for post-compromise cloud-app actions on a mailbox: mailbox access
    (MailItemsAccessed = exfil, T1114.002) and inbox-rule changes (New-InboxRule,
    T1564.008). ``ActionType`` mirrors the actual operation so a hunt for
    ``ActionType has 'Rule'`` / ``'MailItemsAccessed'`` finds the right row.
    """
    ts = _get(rec, "Timestamp", "TimeGenerated", "CreationTime", "time")
    if ts is None:
        return None
    op = _operation(rec) or "MailItemsAccessed"
    mailbox = _get(rec, "MailboxOwnerUPN", "UserId", "RecipientEmailAddress", default="unknown")
    return {
        "Timestamp": ts,
        "ActionType": op,  # New-InboxRule / MailItemsAccessed / Send — mirrors the op
        "AccountId": _get(rec, "UserId", "MailboxOwnerUPN", "AccountId"),
        "AccountDisplayName": _get(rec, "MailboxOwnerUPN", "UserId", "AccountDisplayName", default=mailbox),
        "Application": "Microsoft Exchange Online",
        "IPAddress": _get(rec, "ClientIP", "ClientIPAddress", "IPAddress", default=""),
        "ObjectName": mailbox,
        "RawEventData": str(op),
        "CountryCode": _get(rec, "CountryCode", "Country", default=""),
        "_source": "CloudAppEvents",
    }


# ── helpers ──────────────────────────────────────────────────────────────────


def _coerce_int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _hashish(rec: dict[str, Any]) -> str:
    """Deterministic-ish id from record content (no random — keeps resume stable)."""
    return format(abs(hash(repr(sorted(rec.items(), key=lambda kv: str(kv[0]))))) % (10**12), "012d")


_FUNCS = {
    "to_aad_signin_beta": to_aad_signin_beta,
    "to_email_events": to_email_events,
    "to_url_click_events": to_url_click_events,
    "to_cloud_app_events": to_cloud_app_events,
}

# OfficeActivity routing is operation-aware: each op -> its faithful AH table(s).
_OFFICE_OP_ROUTES: dict[str, list[str]] = {
    "Send": ["to_email_events"],
    "New-InboxRule": ["to_cloud_app_events"],
    "Set-InboxRule": ["to_cloud_app_events"],
    "UpdateInboxRules": ["to_cloud_app_events"],
    "MailItemsAccessed": ["to_cloud_app_events"],
}
# Sign-in tables route unconditionally.
_SIGNIN_ROUTES: dict[str, list[str]] = {
    "SigninLogs": ["to_aad_signin_beta"],
    "AADSignInLogs": ["to_aad_signin_beta"],
}


def _routes_for(sentinel_table: str, rec: dict[str, Any]) -> list[str]:
    if sentinel_table in _SIGNIN_ROUTES:
        return _SIGNIN_ROUTES[sentinel_table]
    if sentinel_table in ("OfficeActivity", "ExchangeOnlineAuditLogs"):
        op = _operation(rec)
        # exact op match first, then a contains-fallback for op variants
        if op in _OFFICE_OP_ROUTES:
            return _OFFICE_OP_ROUTES[op]
        for known, fns in _OFFICE_OP_ROUTES.items():
            if known.lower() in op.lower():
                return fns
        return ["to_cloud_app_events"]  # default: cloud-app activity
    return []


def translate_record(sentinel_table: str, rec: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Return [(ah_table, ah_record), ...] for a Sentinel record (may be empty).

    The ``AttackTechnique`` capture tag is copied onto every translated row so
    the corpus snapshot tags the AH rows as attack telemetry (Phase 10 §6).
    """
    tag = rec.get(ATTACK_TAG_FIELD)
    out: list[tuple[str, dict[str, Any]]] = []
    for fn_name in _routes_for(sentinel_table, rec):
        ah_rec = _FUNCS[fn_name](rec)
        if ah_rec:
            ah_table = ah_rec.pop("_source")
            if tag and ATTACK_TAG_FIELD not in ah_rec:
                ah_rec[ATTACK_TAG_FIELD] = tag
            out.append((ah_table, ah_rec))
    return out


# AH tables this module emits — caller creates these in the emulator before ingest.
XDR_TABLES = ("AADSignInEventsBeta", "EmailEvents", "UrlClickEvents", "CloudAppEvents")

# Canonical example record per AH table — fed to the emulator's
# ``_generate_table_from_example`` to CREATE each table with the right columns
# before dual-emit ingest. Values are type exemplars only.
AH_TABLE_SCHEMAS: dict[str, dict[str, Any]] = {
    "AADSignInEventsBeta": {
        "Timestamp": "2026-01-01T00:00:00Z", "AccountUpn": "u@contoso.com",
        "AccountObjectId": "00000000-0000-0000-0000-000000000000", "AccountDisplayName": "User",
        "IPAddress": "0.0.0.0", "Application": "App", "ApplicationId": "app-id",
        "ResourceDisplayName": "Resource", "ErrorCode": 0, "RiskLevelDuringSignIn": "none",
        "ConditionalAccessStatus": "notApplied", "AuthenticationRequirement": "singleFactorAuthentication",
        "ClientAppUsed": "Browser", "Country": "US", "ReportId": "0",
    },
    "EmailEvents": {
        "Timestamp": "2026-01-01T00:00:00Z", "NetworkMessageId": "msg-id",
        "SenderFromAddress": "sender@external.com", "SenderDisplayName": "Sender",
        "RecipientEmailAddress": "u@contoso.com", "Subject": "Subject",
        "EmailDirection": "Inbound", "DeliveryAction": "Delivered", "ThreatTypes": "Phish",
    },
    "EmailAttachmentInfo": {
        "Timestamp": "2026-01-01T00:00:00Z", "NetworkMessageId": "msg-id",
        "RecipientEmailAddress": "u@contoso.com", "SenderFromAddress": "sender@external.com",
        "FileName": "attachment.docm", "FileType": "docm",
        "SHA256": "0" * 64, "ThreatTypes": "Phish",
    },
    "UrlClickEvents": {
        "Timestamp": "2026-01-01T00:00:00Z", "Url": "https://example.com",
        "UrlChain": ["https://example.com"], "NetworkMessageId": "msg-id",
        "AccountUpn": "u@contoso.com", "RecipientEmailAddress": "u@contoso.com",
        "ActionType": "ClickAllowed", "IsClickedThrough": True, "ThreatTypes": "Phish",
    },
    "CloudAppEvents": {
        "Timestamp": "2026-01-01T00:00:00Z", "ActionType": "MailItemsAccessed",
        "AccountId": "obj-id", "AccountDisplayName": "u@contoso.com",
        "Application": "Microsoft Exchange Online", "IPAddress": "0.0.0.0",
        "ObjectName": "u@contoso.com", "RawEventData": "MailItemsAccessed",
        "CountryCode": "US",
    },
}
