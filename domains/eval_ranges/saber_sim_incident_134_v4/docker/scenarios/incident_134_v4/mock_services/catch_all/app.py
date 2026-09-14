"""Catch-all Azure endpoint responder.

Always-on mock that answers requests to *any* Azure service hostname that does
**not** have a dedicated mock container deployed in the range. Without it, an
agent that sees benign telemetry for a service (e.g. a Key Vault in
``AzureKeyVaultAuditLogs``) and then tries to reach that service's API would get
a hard connection-refused / NXDOMAIN — an obvious "this is a simulation" tell.

Instead this responder returns plausible *authenticated-but-empty* Azure-style
responses (401 when unauthenticated, 200 ``{"value": []}`` for list reads, 404
for specific-resource reads, 403 for writes), shaped by the requested ``Host`` so
a Key Vault host gets a Key Vault error envelope, ARM gets an ARM envelope, etc.

It is wired into the eval (``challenge-net``) compose with DNS aliases for every
known Azure service FQDN that isn't backed by a real mock in that range, and into
the standalone range via the CoreDNS catch-all. Listens on 443 (self-signed TLS,
``curl -sk``) and 80 so any scheme/port resolves.
"""

import os
import threading
from datetime import datetime, timezone

from flask import Flask, request, jsonify, Response
from mock_service_base import MockServiceBase, create_base_blueprint

app = Flask(__name__)
base = MockServiceBase("catch-all")

TENANT_ID = os.environ.get("TENANT_ID", "87654321-4321-4321-4321-cba987654321")
LOGIN_HOST = os.environ.get("LOGIN_HOST", "login.microsoftonline.com")

# Verbs that mutate state — answered with 403 (authenticated but not authorized)
# rather than 200, matching a least-privilege real tenant.
_WRITE_VERBS = {"POST", "PUT", "PATCH", "DELETE"}

# A request whose final path segment names a collection is a "list" read (empty
# collection); a request for a specific named child resource is a 404.
_COLLECTIONS = {
    "secrets", "keys", "certificates", "providers", "resourcegroups",
    "subscriptions", "resources", "users", "groups", "serviceprincipals",
    "applications", "blobs", "containers", "queues", "tables", "databases",
    "value", "values", "items",
}


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _host():
    return (request.headers.get("Host") or request.host or "").split(":")[0].lower()


def _service_kind(host: str) -> str:
    if host.endswith(".vault.azure.net"):
        return "keyvault"
    if host == "management.azure.com" or host.endswith(".management.azure.com"):
        return "arm"
    if host == "graph.microsoft.com" or host.endswith(".graph.microsoft.com"):
        return "graph"
    if host.endswith(".blob.core.windows.net") or host.endswith(".dfs.core.windows.net"):
        return "storage"
    if host.endswith(".queue.core.windows.net") or host.endswith(".table.core.windows.net") \
            or host.endswith(".file.core.windows.net"):
        return "storage"
    if host.endswith(".servicebus.windows.net"):
        return "servicebus"
    if host.endswith(".documents.azure.com"):
        return "cosmos"
    if host.endswith(".azurewebsites.net") or host.endswith(".azurefd.net"):
        return "web"
    return "generic"


def _error_body(kind: str, code: str, message: str):
    """Build a service-appropriate Azure error envelope."""
    if kind == "storage":
        # Storage uses XML for errors.
        xml = (f'<?xml version="1.0" encoding="utf-8"?>'
               f'<Error><Code>{code}</Code><Message>{message}</Message></Error>')
        return Response(xml, mimetype="application/xml")
    # KeyVault / ARM / Graph / generic all use a JSON {"error": {...}} envelope.
    return jsonify({"error": {"code": code, "message": message}})


def _log(host: str, status: int, kind: str):
    base.append_log({
        "TimeGenerated": _now(),
        "source": "catch_all",
        "category": "CatchAllRequest",
        "Host": host,
        "RequestUri": request.full_path,
        "HttpMethod": request.method,
        "ResultStatus": status,
        "ServiceKind": kind,
        "CallerIpAddress": request.remote_addr or "",
        "Authenticated": bool(request.headers.get("Authorization")),
    })


@app.route("/", defaults={"path": ""},
           methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
@app.route("/<path:path>",
           methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
def catch_all(path):
    host = _host()
    kind = _service_kind(host)
    auth = request.headers.get("Authorization", "")

    # 1. Unauthenticated → 401 with a Bearer challenge (real Azure behavior).
    if not auth:
        resp = _error_body(
            kind, "Unauthorized" if kind != "arm" else "AuthenticationFailed",
            "Request is missing a bearer token or authentication credentials.",
        )
        status = 401
        out = (resp, status, {
            "WWW-Authenticate":
                f'Bearer authorization_uri="https://{LOGIN_HOST}/{TENANT_ID}", '
                f'resource="https://{host or "management.azure.com"}"',
        })
        _log(host, status, kind)
        return out

    # 2. Authenticated writes → 403 (least-privilege tenant).
    if request.method in _WRITE_VERBS:
        status = 403
        _log(host, status, kind)
        return _error_body(
            kind, "AuthorizationFailed",
            "The client does not have authorization to perform this action.",
        ), status

    # 3. Authenticated reads. List-style → empty collection; specific → 404.
    segs = [s for s in path.split("/") if s]
    qs = request.query_string.decode("latin-1").lower()
    is_list = (
        not segs
        or segs[-1].lower() in _COLLECTIONS
        or "comp=list" in qs
        or "restype=container" in qs
    )
    if is_list:
        status = 200
        _log(host, status, kind)
        if kind == "storage":
            xml = ('<?xml version="1.0" encoding="utf-8"?>'
                   '<EnumerationResults><Blobs/></EnumerationResults>')
            return Response(xml, mimetype="application/xml"), status
        return jsonify({"value": [], "nextLink": None}), status

    status = 404
    _log(host, status, kind)
    return _error_body(
        kind, "ResourceNotFound" if kind != "keyvault" else "SecretNotFound",
        "The requested resource was not found.",
    ), status


app.register_blueprint(create_base_blueprint(
    base,
    health_extras=lambda: {"role": "catch-all Azure endpoint responder"},
    include_tokens=False,
))


def _run(port, tls):
    kwargs = {"host": "0.0.0.0", "port": port, "debug": False, "threaded": True}
    if tls:
        kwargs["ssl_context"] = "adhoc"
    app.run(**kwargs)


if __name__ == "__main__":
    print("[CATCH_ALL] Starting catch-all Azure endpoint responder (80 + 443)")
    # HTTPS on 443 in a background thread; HTTP on 80 in the main thread.
    threading.Thread(target=_run, args=(443, True), daemon=True).start()
    _run(80, False)
