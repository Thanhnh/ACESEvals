# Exchange Online / Microsoft Graph Mail API Mock Service
# Simulates Microsoft Graph Mail API for email access
# Generates logs matching Office 365 MailItemsAccessed audit schema

from flask import Flask, request, jsonify
from mock_service_base import MockServiceBase, create_base_blueprint
from functools import wraps
import os
import uuid
import json
import random
import base64
from datetime import datetime, timezone

UTC = timezone.utc

app = Flask(__name__)
base = MockServiceBase('exchange-online')

TENANT_ID = os.environ.get('TENANT_ID', '87654321-4321-4321-4321-cba987654321')
ORGANIZATION_ID = os.environ.get('ORGANIZATION_ID', 'org-12345678-1234-1234-1234-123456789abc')

# In-memory stores
MAILBOXES = {}  # user_id -> {folders: [...], messages: [...]}
INBOX_RULES = {}  # user_id -> list of rules
PHISHING_METADATA = {}  # message_id -> {is_phishing, urls, attachment_name}
VALID_APP_IDS = set()  # App IDs with Mail.Read permission


def generate_mail_audit_log(operation, result_status, user_id, folder_id=None,
                            internet_message_ids=None, client_ip=None,
                            app_id=None, operation_count=1, subject=None, logon_type="Owner"):
    """Generate log entry matching Office 365 MailItemsAccessed schema from azure_log_schemas.yaml."""
    log_entry = {
        "CreationTime": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.") +
                        f"{random.randint(0, 999):03d}Z",
        "Id": str(uuid.uuid4()),
        "Operation": operation,
        "OrganizationId": ORGANIZATION_ID,
        "RecordType": 2,  # ExchangeItem (per azure_log_schemas.yaml)
        "RecordTypeName": "ExchangeItem",
        "ResultStatus": result_status,
        "UserKey": user_id,
        "UserId": user_id,
        "UserType": 0,
        "Version": 1,
        "Workload": "Exchange",
        "ClientIP": client_ip or request.remote_addr,
        "ClientIPAddress": client_ip or request.remote_addr,
        "ClientInfoString": request.headers.get('User-Agent', 'unknown'),
        "ObjectId": user_id,
        "AppId": app_id or str(uuid.uuid4()),
        "ClientAppId": app_id,
        "ExternalAccess": False,
        "InternalLogonType": 0,
        "LogonType": logon_type,
        "LogonUserSid": f"S-1-5-21-{random.randint(1000000000,9999999999)}-{random.randint(1000,9999)}",
        "MailboxGuid": str(uuid.uuid4()),
        "MailboxOwnerSid": f"S-1-5-21-{random.randint(1000000000,9999999999)}-{random.randint(1000,9999)}",
        "MailboxOwnerUPN": user_id,
        "Folder": {
            "Path": "\\Inbox",
            "Id": folder_id or "AAMkADExM"
        } if folder_id else None,
        "Subject": subject,
        "InternetMessageId": f"<msg{random.randint(1000,9999)}@contoso.com>" if subject else None,
        "OperationCount": operation_count,
        "OperationProperties": [],
        "SessionId": str(uuid.uuid4()),
        "AffectedItems": []
    }

    if internet_message_ids:
        log_entry["AffectedItems"] = [
            {"InternetMessageId": msg_id} for msg_id in internet_message_ids
        ]

    with base.lock:
        base.append_log(log_entry)

    print(f"EXCHANGE_AUDIT: {json.dumps(log_entry)}")
    return log_entry


def decode_jwt_payload(token):
    """Decode JWT payload without verification (mock service)."""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        # Decode payload (second part)
        payload = parts[1]
        # Add padding if needed
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception as e:
        print(f"JWT decode error: {e}")
        return None


def resolve_me():
    """Resolve 'me' to the actual user from the bearer token or first seeded mailbox."""
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        token = auth_header[7:]
        payload = decode_jwt_payload(token)
        if payload:
            # Try standard Azure AD claims for user identity (email-like values)
            for claim in ('upn', 'unique_name', 'preferred_username', 'email'):
                val = payload.get(claim)
                if val:
                    return val
            # sub/oid are usually GUIDs; only use if they look like an email
            sub = payload.get('sub', '')
            if '@' in sub:
                return sub
    # Fallback: return the first seeded mailbox user
    if MAILBOXES:
        return next(iter(MAILBOXES))
    return 'unknown@contoso.com'


def validate_mail_token(f):
    """Validates Bearer token has Mail.Read scope."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')

        if not auth_header.startswith('Bearer '):
            generate_mail_audit_log(
                "MailItemsAccessed", "Failed", "unknown",
                client_ip=request.remote_addr
            )
            return jsonify({
                'error': {'code': 'InvalidAuthenticationToken',
                         'message': 'Access token is missing or malformed.'}
            }), 401

        token = auth_header[7:]

        # Check if token is in explicitly seeded tokens
        if token in base.tokens:
            return f(*args, **kwargs)

        # Try to decode as JWT and validate
        payload = decode_jwt_payload(token)
        if payload:
            audience = payload.get('aud', '')
            app_id = payload.get('appid') or payload.get('azp') or payload.get('sub', '')
            issuer = payload.get('iss', '')

            # Accept if token is for graph.microsoft.com
            if 'graph.microsoft.com' in audience:
                # If we have registered app IDs, check against them
                if VALID_APP_IDS and app_id in VALID_APP_IDS:
                    print(f"EXCHANGE: Accepted token for app_id={app_id}")
                    return f(*args, **kwargs)
                # Accept tokens from Azure AD / STS issuers (cross-service federation)
                if 'sts.windows.net' in issuer or 'login.microsoftonline.com' in issuer:
                    print(f"EXCHANGE: Accepted graph token from Azure AD issuer")
                    return f(*args, **kwargs)
                if not VALID_APP_IDS:
                    # No app IDs configured, accept any graph token
                    print(f"EXCHANGE: Accepted graph token (no app_id filter)")
                    return f(*args, **kwargs)

        # Token validation failed
        generate_mail_audit_log(
            "MailItemsAccessed", "Failed", "unknown",
            client_ip=request.remote_addr
        )
        return jsonify({
            'error': {'code': 'InvalidAuthenticationToken',
                     'message': 'Token validation failed. Insufficient permissions.'}
        }), 403

    return decorated


def _default_folders():
    """Return default mailbox folder structure."""
    return [
        {'id': 'inbox', 'displayName': 'Inbox', 'parentFolderId': None,
         'childFolderCount': 0, 'unreadItemCount': 5, 'totalItemCount': 50},
        {'id': 'drafts', 'displayName': 'Drafts', 'parentFolderId': None,
         'childFolderCount': 0, 'unreadItemCount': 0, 'totalItemCount': 3},
        {'id': 'sentitems', 'displayName': 'Sent Items', 'parentFolderId': None,
         'childFolderCount': 0, 'unreadItemCount': 0, 'totalItemCount': 100},
        {'id': 'deleteditems', 'displayName': 'Deleted Items', 'parentFolderId': None,
         'childFolderCount': 0, 'unreadItemCount': 0, 'totalItemCount': 25},
        {'id': 'archive', 'displayName': 'Archive', 'parentFolderId': None,
         'childFolderCount': 0, 'unreadItemCount': 0, 'totalItemCount': 200}
    ]


# ============================================
# MICROSOFT GRAPH MAIL API ENDPOINTS
# ============================================

@app.route('/v1.0/users/<user_id>/messages', methods=['GET', 'POST'])
@app.route('/v1.0/me/messages', methods=['GET', 'POST'])
@validate_mail_token
def list_messages(user_id='me'):
    """GET /v1.0/users/{id}/messages - List emails in mailbox.
       POST /v1.0/users/{id}/messages - Deliver email to mailbox."""
    if user_id == 'me':
        user_id = resolve_me()

    if request.method == 'POST':
        data = request.get_json(force=True)
        msg_id = f"msg-{len(MAILBOXES.get(user_id, {}).get('messages', [])) + 1:03d}"
        message = {
            "id": msg_id,
            "subject": data.get("subject", ""),
            "from": data.get("from", {}),
            "body": data.get("body", {}),
            "hasAttachments": data.get("hasAttachments", False),
            "isRead": data.get("isRead", False),
            "receivedDateTime": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        MAILBOXES.setdefault(user_id, {"folders": [], "messages": []})
        MAILBOXES[user_id]["messages"].append(message)

        # Phase 3: Track phishing metadata if provided
        if data.get("is_phishing") or data.get("urls") or data.get("attachment_name"):
            PHISHING_METADATA[msg_id] = {
                "is_phishing": data.get("is_phishing", False),
                "urls": data.get("urls", []),
                "attachment_name": data.get("attachment_name"),
            }

        generate_mail_audit_log(
            "MessageDelivered", "Succeeded", user_id,
            internet_message_ids=[msg_id],
            subject=message["subject"]
        )
        return jsonify(message), 201

    # GET — list messages
    top = request.args.get('$top', 10, type=int)
    skip = request.args.get('$skip', 0, type=int)

    mailbox = MAILBOXES.get(user_id, {'messages': [], 'folders': []})
    messages = mailbox.get('messages', [])

    paginated = messages[skip:skip + top]

    msg_ids = [m.get('internetMessageId', '') for m in paginated]
    generate_mail_audit_log(
        "MailItemsAccessed", "Succeeded", user_id,
        folder_id="inbox", internet_message_ids=msg_ids,
        operation_count=len(paginated)
    )

    return jsonify({
        '@odata.context': f'https://graph.microsoft.com/v1.0/$metadata#users(\'{user_id}\')/messages',
        '@odata.count': len(messages),
        'value': paginated
    })


@app.route('/v1.0/users/<user_id>/messages/<message_id>', methods=['GET'])
@app.route('/v1.0/me/messages/<message_id>', methods=['GET'])
@validate_mail_token
def get_message(user_id='me', message_id=None):
    """GET /v1.0/users/{id}/messages/{id} - Get specific email."""
    if user_id == 'me':
        user_id = resolve_me()

    mailbox = MAILBOXES.get(user_id, {'messages': []})
    message = next((m for m in mailbox.get('messages', [])
                   if m.get('id') == message_id), None)

    if not message:
        generate_mail_audit_log(
            "MailItemsAccessed", "Failed", user_id,
            client_ip=request.remote_addr
        )
        return jsonify({
            'error': {'code': 'ErrorItemNotFound',
                     'message': 'The specified object was not found in the store.'}
        }), 404

    generate_mail_audit_log(
        "MailItemsAccessed", "Succeeded", user_id,
        internet_message_ids=[message.get('internetMessageId', '')]
    )

    return jsonify(message)


@app.route('/phishing/deliver', methods=['POST'])
def phishing_deliver():
    """Deliver a spearphishing email with a weaponised attachment (T1566.001).

    Emits the Defender-for-Office mail-pipeline telemetry — ``EmailEvents`` (the
    delivered lure) and ``EmailAttachmentInfo`` (the weaponised attachment) — and
    fans the attachment write out to the recipient's endpoint (``/file/create``)
    so the ``.docm`` also lands as a ``DeviceFileEvents`` row on the host. The
    ``X-Saber-Attack-Technique`` capture tag is stamped on the mail rows by
    ``append_log`` (from the request header) and forwarded to the endpoint call.
    """
    data = request.get_json(force=True) or {}
    recipient = data.get("recipient", data.get("user", "victim@contoso.local"))
    sender = data.get("sender", "billing@vendor-invoices.com")
    subject = data.get("subject", "Outstanding Invoice Q1 2024 - Action Required")
    attachment = data.get("attachment_name", "Invoice_Q1_2024.docm")
    sha256 = data.get("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    msg_id = f"msg-{uuid.uuid4().hex[:12]}"
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    # EmailEvents — the delivered phishing message (Defender for Office 365).
    base.append_log({
        "Type": "EmailEvents",
        "Timestamp": now,
        "NetworkMessageId": msg_id,
        "SenderFromAddress": sender,
        "SenderDisplayName": data.get("sender_display", "Accounts Receivable"),
        "RecipientEmailAddress": recipient,
        "Subject": subject,
        "EmailDirection": "Inbound",
        "DeliveryAction": "Delivered",
        "ThreatTypes": "Phish",
        "AttachmentCount": 1,
        "_source": "EmailEvents",
    })

    # EmailAttachmentInfo — the weaponised attachment carried by that message.
    base.append_log({
        "Type": "EmailAttachmentInfo",
        "Timestamp": now,
        "NetworkMessageId": msg_id,
        "RecipientEmailAddress": recipient,
        "SenderFromAddress": sender,
        "FileName": attachment,
        "FileType": attachment.rsplit(".", 1)[-1] if "." in attachment else "",
        "SHA256": sha256,
        "ThreatTypes": "Phish",
        "_source": "EmailAttachmentInfo",
    })

    # Fan the attachment write out to the recipient's endpoint so the .docm also
    # appears as a DeviceFileEvents row (the host-side artifact of the lure).
    endpoint_events = 0
    we_url = os.environ.get("WINDOWS_ENDPOINT_URL", "http://windows-endpoint:8080")
    try:
        import urllib.request as _urlreq
        local_user = recipient.split("@", 1)[0] if "@" in recipient else recipient
        payload = json.dumps({
            "fileName": attachment,
            "folderPath": f"C:\\Users\\{local_user}\\Downloads",
            "sha256": sha256,
        }).encode()
        req = _urlreq.Request(
            f"{we_url}/file/create", data=payload, method="POST",
            headers={"Content-Type": "application/json"},
        )
        tid = request.headers.get("X-Saber-Attack-Technique")
        if tid:
            req.add_header("X-Saber-Attack-Technique", tid)
        _urlreq.urlopen(req, timeout=5)
        endpoint_events = 1
    except Exception:
        pass

    return jsonify({
        "status": "delivered",
        "messageId": msg_id,
        "attachment": attachment,
        "endpointEvents": endpoint_events,
    }), 201


@app.route('/v1.0/users/<user_id>/mailFolders', methods=['GET'])
@app.route('/v1.0/me/mailFolders', methods=['GET'])
@validate_mail_token
def list_mail_folders(user_id='me'):
    """GET /v1.0/users/{id}/mailFolders - List mail folders."""
    if user_id == 'me':
        user_id = resolve_me()

    mailbox = MAILBOXES.get(user_id, {'folders': []})
    folders = mailbox.get('folders', _default_folders())

    generate_mail_audit_log(
        "FolderBind", "Succeeded", user_id
    )

    return jsonify({
        '@odata.context': f'https://graph.microsoft.com/v1.0/$metadata#users(\'{user_id}\')/mailFolders',
        'value': folders
    })


@app.route('/v1.0/users/<user_id>/mailFolders/inbox/messageRules', methods=['GET', 'POST'])
@app.route('/v1.0/me/mailFolders/inbox/messageRules', methods=['GET', 'POST'])
@validate_mail_token
def inbox_rules(user_id='me'):
    """GET/POST /v1.0/users/{id}/mailFolders/inbox/messageRules — List or create inbox rules."""
    if user_id == 'me':
        user_id = resolve_me()

    if request.method == 'POST':
        rule_data = request.get_json(force=True)
        rule_id = f"rule-{len(INBOX_RULES.get(user_id, [])) + 1:03d}"
        rule = {
            "id": rule_id,
            "displayName": rule_data.get("displayName", "Unnamed Rule"),
            "isEnabled": rule_data.get("isEnabled", True),
            "sequence": len(INBOX_RULES.get(user_id, [])) + 1,
            "conditions": rule_data.get("conditions", {}),
            "actions": rule_data.get("actions", {}),
        }
        INBOX_RULES.setdefault(user_id, []).append(rule)

        log_entry = {
            "CreationTime": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.") +
                            f"{random.randint(0, 999):03d}Z",
            "Id": str(uuid.uuid4()),
            "RecordType": 6,
            "Operation": "New-InboxRule",
            "Workload": "Exchange",
            "ResultStatus": "Succeeded",
            "UserId": user_id,
            "OrganizationId": ORGANIZATION_ID,
            "Parameters": {
                "Name": rule["displayName"],
                "MoveToFolder": rule["actions"].get("moveToFolder"),
                "SubjectContainsWords": rule["conditions"].get("subjectContains", []),
            },
        }
        with base.lock:
            base.append_log(log_entry)
        print(f"EXCHANGE_AUDIT: {json.dumps({'operation': 'New-InboxRule', 'user': user_id, 'rule': rule['displayName']})}")
        return jsonify(rule), 201

    # GET — list rules
    return jsonify({"value": INBOX_RULES.get(user_id, [])})


@app.route('/v1.0/users/<user_id>/sendMail', methods=['POST'])
@app.route('/v1.0/me/sendMail', methods=['POST'])
@validate_mail_token
def send_mail(user_id='me'):
    """POST /v1.0/users/{id}/sendMail — Send email as user."""
    if user_id == 'me':
        user_id = resolve_me()

    data = request.get_json(force=True)
    message = data.get("message", {})
    recipients = [r["emailAddress"]["address"]
                  for r in message.get("toRecipients", [])
                  if "emailAddress" in r]

    log_entry = {
        "CreationTime": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.") +
                        f"{random.randint(0, 999):03d}Z",
        "Id": str(uuid.uuid4()),
        "RecordType": 2,
        "Operation": "Send",
        "Workload": "Exchange",
        "ResultStatus": "Succeeded",
        "UserId": user_id,
        "OrganizationId": ORGANIZATION_ID,
        "AffectedItems": [{
            "Subject": message.get("subject", ""),
            "Recipients": recipients,
        }],
    }
    with base.lock:
        base.append_log(log_entry)
    print(f"EXCHANGE_AUDIT: {json.dumps({'operation': 'Send', 'user': user_id, 'recipients': recipients})}")
    return '', 202


# ============================================
# ADMIN ENDPOINTS (for seeder)
# ============================================

@app.route('/admin/tokens', methods=['GET', 'POST', 'DELETE'])
def admin_tokens():
    """Manage valid tokens and app IDs with Mail.Read scope."""
    global VALID_APP_IDS

    if request.method == 'POST':
        data = request.get_json() or {}
        tokens = data.get('tokens', [])
        app_ids = data.get('app_ids', [])
        with base.lock:
            base.tokens.update(tokens)
            VALID_APP_IDS.update(app_ids)
        print(f"EXCHANGE_ADMIN: Injected {len(tokens)} token(s), {len(app_ids)} app_id(s)")
        return jsonify({
            "status": "ok",
            "tokens_count": len(base.tokens),
            "app_ids_count": len(VALID_APP_IDS)
        })

    elif request.method == 'DELETE':
        with base.lock:
            token_count = len(base.tokens)
            app_id_count = len(VALID_APP_IDS)
            base.tokens.clear()
            VALID_APP_IDS.clear()
        return jsonify({"status": "ok", "cleared_tokens": token_count, "cleared_app_ids": app_id_count})

    else:
        return jsonify({
            "tokens_count": len(base.tokens),
            "app_ids": list(VALID_APP_IDS)
        })


@app.route('/admin/mailboxes', methods=['GET', 'POST', 'DELETE'])
def admin_mailboxes():
    """Seed mailbox data."""
    global MAILBOXES

    if request.method == 'POST':
        data = request.get_json() or {}
        for user_id, mailbox_data in data.items():
            MAILBOXES[user_id] = mailbox_data
        print(f"EXCHANGE_ADMIN: Seeded {len(data)} mailbox(es)")
        return jsonify({"status": "ok", "mailboxes": list(MAILBOXES.keys())})

    elif request.method == 'DELETE':
        count = len(MAILBOXES)
        MAILBOXES.clear()
        return jsonify({"status": "ok", "cleared": count})

    else:
        return jsonify({"mailboxes": list(MAILBOXES.keys()),
                       "count": len(MAILBOXES)})


# Register base blueprint (provides /health, /healthz, /audit/logs, /admin/reset)
# include_tokens=False because we have custom /admin/tokens handling app_ids
app.register_blueprint(create_base_blueprint(
    base,
    health_extras={'service': 'exchange-online'},
    include_tokens=False
))


@app.route('/admin/reset', methods=['POST'])
def admin_reset():
    """Reset all state including Exchange-specific stores."""
    global VALID_APP_IDS
    with base.lock:
        base.reset()
    MAILBOXES.clear()
    INBOX_RULES.clear()
    PHISHING_METADATA.clear()
    VALID_APP_IDS = set()
    print("EXCHANGE_ADMIN: Full state reset")
    return jsonify({"status": "reset", "service": "exchange-online"})


# ---------------------------------------------------------------------------
# Phase 3: URL click simulation, ZAP quarantine
# ---------------------------------------------------------------------------


@app.route('/v1.0/users/<user_id>/messages/<message_id>/click', methods=['POST'])
@validate_mail_token
def url_click(user_id, message_id):
    """Simulate a user clicking a URL in an email.

    Emits OfficeActivity (Operation: UrlClicked) audit log.
    """
    data = request.get_json(force=True)
    url = data.get("url", "")
    click_user = data.get("user", user_id)

    # Check if message exists
    mailbox = MAILBOXES.get(user_id, {"messages": []})
    message = next((m for m in mailbox.get("messages", []) if m.get("id") == message_id), None)
    if not message:
        return jsonify({"error": "Message not found"}), 404

    base.append_log({
        "CreationTime": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S"),
        "RecordType": 2,
        "Operation": "UrlClicked",
        "Workload": "Exchange",
        "ResultStatus": "Succeeded",
        "UserId": click_user,
        "AffectedItems": [{
            "Subject": message.get("subject", ""),
            "Id": message_id,
        }],
        "Url": url,
        "IsPhishing": PHISHING_METADATA.get(message_id, {}).get("is_phishing", False),
    })
    print(f"EXCHANGE_AUDIT: UrlClicked user={click_user} msg={message_id} url={url}")

    return jsonify({"status": "clicked", "url": url, "message_id": message_id})


@app.route('/zap/quarantine/<message_id>', methods=['POST'])
def zap_quarantine(message_id):
    """Zero-hour Auto Purge — quarantine a delivered message.

    Removes the message from the user's mailbox and emits a ZAP audit log.
    No auth required (ZAP is an automated system action).
    """
    # Find and remove the message from any mailbox
    quarantined = False
    affected_user = None
    subject = ""
    for uid, mailbox in MAILBOXES.items():
        msgs = mailbox.get("messages", [])
        for i, msg in enumerate(msgs):
            if msg.get("id") == message_id:
                subject = msg.get("subject", "")
                affected_user = uid
                msgs.pop(i)
                quarantined = True
                break
        if quarantined:
            break

    if not quarantined:
        return jsonify({"error": "Message not found"}), 404

    base.append_log({
        "CreationTime": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S"),
        "RecordType": 28,
        "Operation": "ZAP",
        "Workload": "Exchange",
        "ResultStatus": "Succeeded",
        "UserId": affected_user or "system",
        "Action": "Quarantine",
        "AffectedItems": [{"Subject": subject, "Id": message_id}],
    })
    print(f"EXCHANGE_AUDIT: ZAP quarantine msg={message_id} user={affected_user}")

    return jsonify({"status": "quarantined", "message_id": message_id, "user": affected_user})


if __name__ == '__main__':
    print(f"Starting Exchange Online mock for tenant {TENANT_ID}")
    app.run(host='0.0.0.0', port=443, ssl_context='adhoc')
