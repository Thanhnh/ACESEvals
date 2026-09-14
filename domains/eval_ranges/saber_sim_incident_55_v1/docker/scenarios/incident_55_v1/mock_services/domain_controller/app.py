"""
Mock Windows Domain Controller Service

Simulates a Windows Domain Controller with:
- LDAP directory queries (port 389)
- Kerberos authentication (port 88)
- REST API for admin/audit (port 8080)

Generates Windows Security Events as a result of protocol interactions.
"""

import os
import json
import secrets
import time
import uuid
import random
import base64
import threading
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify
import yaml
from mock_service_base import MockServiceBase, create_base_blueprint

# ============================================================================
# Configuration
# ============================================================================

CONFIG_PATH = os.environ.get('CONFIG_PATH', '/app/config.yaml')
DOMAIN = os.environ.get('DOMAIN', 'CORP.LOCAL')
DC_NAME = os.environ.get('DC_NAME', 'DC')
SUBSCRIPTION_ID = os.environ.get('SUBSCRIPTION_ID', '12345678-1234-1234-1234-123456789abc')
RESOURCE_GROUP = os.environ.get('RESOURCE_GROUP', 'production-rg')

base = MockServiceBase('domain-controller')

# In-memory stores
USERS = {}           # username -> user object
GROUPS = {}          # group_name -> group object
COMPUTERS = {}       # computer_name -> computer object
SERVICE_PRINCIPALS = {}  # SPN -> service info
KERBEROS_TICKETS = {} # ticket_id -> ticket info (TGTs and service tickets)
REPLICATION_LOG = []  # DCSync audit trail
SID_HISTORY = {}     # username -> [sid, ...]

CONFIG = {}

# ============================================================================
# Data Models
# ============================================================================

DEFAULT_USERS = [
    {"samAccountName": "Administrator", "sid": "S-1-5-21-3623811015-3361044348-30300820-500", "memberOf": ["Domain Admins", "Administrators"], "enabled": True},
    {"samAccountName": "krbtgt", "sid": "S-1-5-21-3623811015-3361044348-30300820-502", "memberOf": [], "enabled": False},
    {"samAccountName": "Guest", "sid": "S-1-5-21-3623811015-3361044348-30300820-501", "memberOf": ["Guests"], "enabled": False},
    {"samAccountName": "svc_backup", "sid": "S-1-5-21-3623811015-3361044348-30300820-1001", "memberOf": ["Backup Operators"], "enabled": True},
    {"samAccountName": "svc_sql", "sid": "S-1-5-21-3623811015-3361044348-30300820-1002", "memberOf": ["Service Accounts"], "enabled": True},
    {"samAccountName": "john.doe", "sid": "S-1-5-21-3623811015-3361044348-30300820-1101", "memberOf": ["Domain Users", "IT Support"], "enabled": True},
    {"samAccountName": "jane.smith", "sid": "S-1-5-21-3623811015-3361044348-30300820-1102", "memberOf": ["Domain Users", "HR"], "enabled": True},
    {"samAccountName": "admin.ops", "sid": "S-1-5-21-3623811015-3361044348-30300820-1103", "memberOf": ["Domain Admins", "IT Support"], "enabled": True},
]

DEFAULT_GROUPS = [
    {"name": "Domain Admins", "sid": "S-1-5-21-3623811015-3361044348-30300820-512", "members": ["Administrator", "admin.ops"]},
    {"name": "Domain Users", "sid": "S-1-5-21-3623811015-3361044348-30300820-513", "members": ["john.doe", "jane.smith"]},
    {"name": "Administrators", "sid": "S-1-5-32-544", "members": ["Administrator"]},
    {"name": "Backup Operators", "sid": "S-1-5-32-551", "members": ["svc_backup"]},
    {"name": "Service Accounts", "sid": "S-1-5-21-3623811015-3361044348-30300820-1200", "members": ["svc_backup", "svc_sql"]},
]

DEFAULT_SPNS = [
    {"spn": "cifs/dc.corp.local", "account": "DC$", "sid": "S-1-5-21-3623811015-3361044348-30300820-1000"},
    {"spn": "ldap/dc.corp.local", "account": "DC$", "sid": "S-1-5-21-3623811015-3361044348-30300820-1000"},
    {"spn": "MSSQLSvc/sql01.corp.local:1433", "account": "svc_sql", "sid": "S-1-5-21-3623811015-3361044348-30300820-1002"},
    {"spn": "HTTP/web01.corp.local", "account": "svc_web", "sid": "S-1-5-21-3623811015-3361044348-30300820-1003"},
]

DEFAULT_COMPUTERS = [
    {"name": "DC", "os": "Windows Server 2022", "ip": "172.30.10.60"},
    {"name": "WEB01", "os": "Windows Server 2022", "ip": "172.30.20.10"},
    {"name": "SQL01", "os": "Windows Server 2022", "ip": "172.30.10.50"},
]

# ============================================================================
# Windows Security Event Generation
# ============================================================================

def generate_security_event(event_id: int, details: dict) -> dict:
    """Generate a Windows Security Event in Azure Monitor format."""

    event_descriptions = {
        4624: "An account was successfully logged on",
        4625: "An account failed to log on",
        4661: "A handle to an object was requested",
        4662: "An operation was performed on an object",
        4720: "A user account was created",
        4724: "An attempt was made to reset an account's password",
        4728: "A member was added to a security-enabled global group",
        4765: "SID History was added to an account",
        4768: "A Kerberos authentication ticket (TGT) was requested",
        4769: "A Kerberos service ticket was requested",
        4771: "Kerberos pre-authentication failed",
        4776: "The computer attempted to validate the credentials for an account",
        4672: "Special privileges assigned to new logon",
    }

    now = datetime.now(timezone.utc)

    event = {
        "time": now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{random.randint(0, 9999999):07d}Z",
        "category": "SecurityEvent",
        "operationName": f"SecurityEvent_{event_id}",
        "resultType": details.get("resultType", "Success"),
        "resourceId": f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.Compute/virtualMachines/{DC_NAME}",
        "properties": {
            "EventID": event_id,
            "Computer": f"{DC_NAME}.{DOMAIN}",
            "Channel": "Security",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Level": "Information" if details.get("resultType") != "Failure" else "Warning",
            "Description": event_descriptions.get(event_id, "Security event"),
            "EventData": details.get("eventData", {}),
        },
        "_source": "domain_controller"
    }

    base.append_log(event)

    print(f"DC_EVENT: {json.dumps(event)}")
    return event

# ============================================================================
# LDAP Protocol Handler (Port 389)
# ============================================================================

ldap_app = Flask('ldap')

@ldap_app.route('/health', methods=['GET'])
def ldap_health():
    return jsonify({"status": "healthy", "service": "ldap", "port": 389})

@ldap_app.route('/search', methods=['POST'])
def ldap_search():
    """
    Simulate LDAP search query.

    Real LDAP uses binary protocol, but we simulate via REST.
    Generates Event 4662 (Directory Service Access) for sensitive queries.
    """
    data = request.get_json() or {}
    base_dn = data.get('baseDN', f'DC={DOMAIN.replace(".", ",DC=")}')
    filter_str = data.get('filter', '(objectClass=*)')
    attributes = data.get('attributes', ['*'])

    caller_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    caller_user = request.headers.get('X-Auth-User', 'anonymous')

    # Parse simple filters
    results = []

    if 'objectClass=user' in filter_str or 'objectCategory=person' in filter_str:
        results = list(USERS.values())
    elif 'objectClass=group' in filter_str:
        results = list(GROUPS.values())
    elif 'objectClass=computer' in filter_str:
        results = list(COMPUTERS.values())
    elif 'servicePrincipalName=' in filter_str:
        # SPN query - used in Kerberoasting
        spn_filter = filter_str.split('servicePrincipalName=')[1].split(')')[0]
        results = [s for s in SERVICE_PRINCIPALS.values() if spn_filter in s.get('spn', '')]
    else:
        results = list(USERS.values()) + list(GROUPS.values())

    # Generate Event 4662 - Directory Service Access
    generate_security_event(4662, {
        "resultType": "Success",
        "eventData": {
            "SubjectUserName": caller_user,
            "SubjectDomainName": DOMAIN.split('.')[0],
            "ObjectServer": "DS",
            "ObjectType": "(%{bf967aba-0de6-11d0-a285-00aa003049e2})",  # User object GUID
            "ObjectName": base_dn,
            "OperationType": "Object Access",
            "AccessMask": "0x100",  # Read property
            "Properties": filter_str,
            "IpAddress": caller_ip,
            "IpPort": str(random.randint(49152, 65535)),
        }
    })

    return jsonify({
        "resultCode": 0,
        "matchedDN": base_dn,
        "entries": results[:100],  # Limit results
        "referrals": []
    })

@ldap_app.route('/bind', methods=['POST'])
def ldap_bind():
    """
    Simulate LDAP bind (authentication).
    Generates Event 4624/4625 for success/failure.
    """
    data = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')
    bind_type = data.get('bindType', 'simple')  # simple, sasl, ntlm

    caller_ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    # Check if user exists
    user = USERS.get(username.lower())

    # Simulate authentication (accept any password for existing users)
    if user and user.get('enabled', True):
        # Success - Event 4624
        generate_security_event(4624, {
            "resultType": "Success",
            "eventData": {
                "SubjectUserName": "-",
                "SubjectDomainName": "-",
                "TargetUserName": username,
                "TargetDomainName": DOMAIN.split('.')[0],
                "LogonType": 3,  # Network logon
                "LogonProcessName": "NtLmSsp" if bind_type == 'ntlm' else "Kerberos",
                "AuthenticationPackageName": "NTLM" if bind_type == 'ntlm' else "Kerberos",
                "WorkstationName": "-",
                "LogonGuid": str(uuid.uuid4()),
                "IpAddress": caller_ip,
                "IpPort": str(random.randint(49152, 65535)),
            }
        })

        return jsonify({
            "resultCode": 0,
            "message": "Bind successful",
            "bindDN": f"CN={username},CN=Users,DC={DOMAIN.replace('.', ',DC=')}"
        })
    else:
        # Failure - Event 4625
        generate_security_event(4625, {
            "resultType": "Failure",
            "eventData": {
                "SubjectUserName": "-",
                "SubjectDomainName": "-",
                "TargetUserName": username,
                "TargetDomainName": DOMAIN.split('.')[0],
                "LogonType": 3,
                "Status": "0xc000006d",  # STATUS_LOGON_FAILURE
                "SubStatus": "0xc0000064" if not user else "0xc000006a",  # Bad username or bad password
                "FailureReason": "Unknown user name or bad password",
                "IpAddress": caller_ip,
                "IpPort": str(random.randint(49152, 65535)),
            }
        })

        return jsonify({"resultCode": 49, "message": "Invalid credentials"}), 401


@ldap_app.route('/query', methods=['POST'])
def ldap_query():
    """Execute a structured LDAP query against the mock AD database.

    More structured than /search — accepts base_dn, filter, and attributes
    explicitly and returns formatted AD entries.
    """
    data = request.get_json() or {}
    base_dn = data.get('base_dn', f'DC={DOMAIN.replace(".", ",DC=")}')
    filter_str = data.get('filter', '(objectClass=*)')
    attributes = data.get('attributes', ['sAMAccountName', 'memberOf'])
    source_host = data.get('source_host', 'unknown')
    source_user = data.get('source_user', request.headers.get('X-Auth-User', 'anonymous'))

    entries = []
    with base.lock:
        if 'objectClass=user' in filter_str or 'objectCategory=person' in filter_str:
            for uname, user in USERS.items():
                entry = {
                    'dn': f"CN={user.get('samAccountName', uname)},OU=Users,{base_dn}",
                    'attributes': {attr: user.get(attr, user.get(attr.lower(), ''))
                                   for attr in attributes},
                }
                entries.append(entry)
        elif 'objectClass=group' in filter_str:
            for gname, group in GROUPS.items():
                entry = {
                    'dn': f"CN={gname},OU=Groups,{base_dn}",
                    'attributes': {'name': gname, 'members': group.get('members', [])},
                }
                entries.append(entry)
        elif 'servicePrincipalName' in filter_str:
            for spn, info in SERVICE_PRINCIPALS.items():
                entry = {
                    'dn': f"CN={info.get('account', 'unknown')},OU=Services,{base_dn}",
                    'attributes': {'servicePrincipalName': spn, 'sAMAccountName': info.get('account', '')},
                }
                entries.append(entry)
        else:
            for uname, user in USERS.items():
                entries.append({
                    'dn': f"CN={user.get('samAccountName', uname)},OU=Users,{base_dn}",
                    'attributes': {attr: user.get(attr, '') for attr in attributes},
                })

    generate_security_event(4662, {
        "resultType": "Success",
        "eventData": {
            "SubjectUserName": source_user,
            "SubjectDomainName": DOMAIN.split('.')[0],
            "ObjectServer": "DS",
            "ObjectType": "(%{bf967aba-0de6-11d0-a285-00aa003049e2})",
            "ObjectName": base_dn,
            "OperationType": "Object Access",
            "AccessMask": "0x100",
            "Properties": filter_str,
            "SourceHost": source_host,
        }
    })

    return jsonify({"entries": entries, "count": len(entries)})


@ldap_app.route('/recon', methods=['POST'])
def ldap_recon():
    """Bulk AD recon commands (whoami, net user, net group).

    Typically the first step after initial access — simulates common
    enumeration commands run by attackers.
    """
    data = request.get_json() or {}
    commands = data.get('commands', [])
    source_host = data.get('source_host', 'unknown')
    source_user = data.get('source_user', 'anonymous')

    results = {}
    with base.lock:
        for cmd in commands:
            cmd_lower = cmd.lower().strip()
            if 'whoami' in cmd_lower:
                user = USERS.get(source_user.lower(), {})
                results['whoami'] = {
                    'user': f"{DOMAIN.split('.')[0]}\\{source_user}",
                    'groups': user.get('memberOf', []),
                    'privileges': ['SeChangeNotifyPrivilege'],
                }
                if any(g in ('Domain Admins', 'Administrators') for g in user.get('memberOf', [])):
                    results['whoami']['privileges'].extend([
                        'SeDebugPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege',
                    ])
            elif 'net user' in cmd_lower and '/domain' in cmd_lower:
                results['net_user'] = sorted(USERS.keys())
            elif 'net group' in cmd_lower and 'domain admins' in cmd_lower:
                admins_group = GROUPS.get('Domain Admins', {})
                results['net_group_domain_admins'] = admins_group.get('members', [])
            elif 'net group' in cmd_lower and '/domain' in cmd_lower:
                results['net_group'] = sorted(GROUPS.keys())
            elif 'net localgroup' in cmd_lower:
                results['net_localgroup'] = ['Administrators', 'Backup Operators', 'Remote Desktop Users']

    # Event 4661 — Directory object enumeration
    generate_security_event(4661, {
        "resultType": "Success",
        "eventData": {
            "SubjectUserName": source_user,
            "SubjectDomainName": DOMAIN.split('.')[0],
            "ObjectServer": "DS",
            "ObjectType": "SAM_DOMAIN",
            "ObjectName": DOMAIN,
            "HandleId": str(random.randint(100, 9999)),
            "AccessMask": "0x211b",
            "SourceHost": source_host,
            "Commands": commands,
        }
    })

    return jsonify({"results": results})


# ============================================================================
# Kerberos Protocol Handler (Port 88)
# ============================================================================

kerberos_app = Flask('kerberos')

@kerberos_app.route('/health', methods=['GET'])
def kerberos_health():
    return jsonify({"status": "healthy", "service": "kerberos", "port": 88})

@kerberos_app.route('/as-req', methods=['POST'])
def kerberos_as_req():
    """
    Simulate Kerberos AS-REQ (TGT request).
    Generates Event 4768 (Kerberos TGT Request).
    """
    data = request.get_json() or {}
    client_principal = data.get('clientPrincipal', '')  # user@REALM
    password = data.get('password', '')
    pre_auth = data.get('preAuthentication', True)

    caller_ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    # Extract username from principal
    username = client_principal.split('@')[0] if '@' in client_principal else client_principal
    user = USERS.get(username.lower())

    if user and user.get('enabled', True):
        # Generate TGT
        tgt_id = str(uuid.uuid4())
        now = datetime.utcnow()
        tgt = {
            "ticketId": tgt_id,
            "clientPrincipal": f"{username}@{DOMAIN}",
            "serverPrincipal": f"krbtgt/{DOMAIN}@{DOMAIN}",
            "startTime": now.isoformat(),
            "endTime": (now + timedelta(hours=10)).isoformat(),
            "flags": ["forwardable", "renewable", "initial"],
        }
        with base.lock:
            KERBEROS_TICKETS[tgt_id] = tgt

        # Event 4768 - TGT Requested (Success)
        generate_security_event(4768, {
            "resultType": "Success",
            "eventData": {
                "TargetUserName": username,
                "TargetDomainName": DOMAIN.split('.')[0],
                "ServiceName": "krbtgt",
                "ServiceSid": "S-1-5-21-3623811015-3361044348-30300820-502",
                "TicketOptions": "0x40810010",
                "Status": "0x0",
                "TicketEncryptionType": "0x12",  # AES256
                "PreAuthType": "2" if pre_auth else "0",
                "IpAddress": f"::ffff:{caller_ip}",
                "IpPort": str(random.randint(49152, 65535)),
                "CertIssuerName": "",
                "CertSerialNumber": "",
            }
        })

        return jsonify({
            "resultCode": 0,
            "tgt": tgt_id,  # In reality this would be encrypted blob
            "sessionKey": str(uuid.uuid4())[:16],
        })
    else:
        # Event 4768 - TGT Request Failed
        generate_security_event(4768, {
            "resultType": "Failure",
            "eventData": {
                "TargetUserName": username,
                "TargetDomainName": DOMAIN.split('.')[0],
                "ServiceName": "krbtgt",
                "Status": "0x6" if not user else "0x18",  # Client not found or Pre-auth failed
                "TicketOptions": "0x40810010",
                "TicketEncryptionType": "0x12",
                "PreAuthType": "0",
                "IpAddress": f"::ffff:{caller_ip}",
                "IpPort": str(random.randint(49152, 65535)),
            }
        })

        return jsonify({"resultCode": 6, "message": "Client not found in database"}), 401

@kerberos_app.route('/tgs-req', methods=['POST'])
def kerberos_tgs_req():
    """
    Simulate Kerberos TGS-REQ (Service Ticket request).
    Generates Event 4769 (Kerberos Service Ticket Request).

    This is the endpoint targeted in Kerberoasting attacks.
    """
    data = request.get_json() or {}
    tgt = data.get('tgt', '')
    spn = data.get('servicePrincipal', '')  # e.g., MSSQLSvc/sql01.corp.local:1433

    caller_ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    # Validate TGT exists (thread-safe)
    with base.lock:
        tgt_info = KERBEROS_TICKETS.get(tgt)
    if not tgt_info:
        return jsonify({"resultCode": 31, "message": "TGT expired or invalid"}), 401

    username = tgt_info['clientPrincipal'].split('@')[0]

    # Check if SPN exists (thread-safe)
    with base.lock:
        spn_info = SERVICE_PRINCIPALS.get(spn)
    service_account = spn_info.get('account', 'unknown') if spn_info else 'unknown'

    # Generate service ticket
    st_id = str(uuid.uuid4())
    now = datetime.utcnow()
    service_ticket = {
        "ticketId": st_id,
        "clientPrincipal": tgt_info['clientPrincipal'],
        "serverPrincipal": spn,
        "startTime": now.isoformat(),
        "endTime": (now + timedelta(hours=10)).isoformat(),
    }
    with base.lock:
        KERBEROS_TICKETS[st_id] = service_ticket

    # Event 4769 - Service Ticket Requested
    # Note: This is logged even for non-existent SPNs (useful for Kerberoasting detection)
    generate_security_event(4769, {
        "resultType": "Success",
        "eventData": {
            "TargetUserName": username,
            "TargetDomainName": DOMAIN.split('.')[0],
            "ServiceName": spn.split('/')[0] if '/' in spn else spn,
            "ServiceSid": spn_info.get('sid', 'S-1-0-0') if spn_info else "S-1-0-0",
            "TicketOptions": "0x40810000",
            "Status": "0x0",
            "TicketEncryptionType": "0x17",  # RC4 (common in Kerberoasting)
            "IpAddress": f"::ffff:{caller_ip}",
            "IpPort": str(random.randint(49152, 65535)),
            "TransmittedServices": "-",
        }
    })

    return jsonify({
        "resultCode": 0,
        "serviceTicket": st_id,
        "sessionKey": str(uuid.uuid4())[:16],
    })


@kerberos_app.route('/overpass', methods=['POST'])
def kerberos_overpass():
    """Overpass-the-Hash: convert NTLM hash into Kerberos TGT.

    Used when an attacker has a stolen NTLM hash (from LSASS dump) and wants
    to obtain a Kerberos TGT without knowing the plaintext password.
    """
    data = request.get_json() or {}
    ntlm_hash = data.get('ntlm_hash', '')
    target_user = data.get('target_user', '')
    source_host = data.get('source_host', 'unknown')

    caller_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    user = USERS.get(target_user.lower())

    if not user:
        return jsonify({"resultCode": 6, "message": "Target user not found"}), 404

    # Generate TGT via hash (anomalous — RC4 encryption type)
    tgt_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    tgt = {
        "ticketId": tgt_id,
        "clientPrincipal": f"{target_user}@{DOMAIN}",
        "serverPrincipal": f"krbtgt/{DOMAIN}@{DOMAIN}",
        "startTime": now.isoformat(),
        "endTime": (now + timedelta(hours=10)).isoformat(),
        "flags": ["forwardable", "renewable", "initial"],
        "_overpass": True,
    }
    with base.lock:
        KERBEROS_TICKETS[tgt_id] = tgt

    # Event 4768 with RC4 encryption type — anomalous indicator
    generate_security_event(4768, {
        "resultType": "Success",
        "eventData": {
            "TargetUserName": target_user,
            "TargetDomainName": DOMAIN.split('.')[0],
            "ServiceName": "krbtgt",
            "ServiceSid": "S-1-5-21-3623811015-3361044348-30300820-502",
            "TicketOptions": "0x40810010",
            "Status": "0x0",
            "TicketEncryptionType": "0x17",  # RC4 — anomalous for overpass
            "PreAuthType": "0",  # No pre-auth (hash-based)
            "IpAddress": f"::ffff:{caller_ip}",
            "SourceHost": source_host,
            "_alert": "overpass_the_hash",
        }
    })

    return jsonify({
        "resultCode": 0,
        "tgt": tgt_id,
        "sessionKey": str(uuid.uuid4())[:16],
        "encryptionType": "RC4_HMAC",
        "principal": f"{target_user}@{DOMAIN}",
    })


# ============================================================================
# HTTP Admin/Audit API (Port 8080)
# ============================================================================

admin_app = Flask('admin')

# Register base blueprint on admin_app (provides /health, /healthz, /audit/logs, /admin/reset)
admin_app.register_blueprint(create_base_blueprint(
    base,
    health_extras=lambda: {
        'domain': DOMAIN,
        'dc': DC_NAME,
        'users': len(USERS),
        'groups': len(GROUPS),
        'spns': len(SERVICE_PRINCIPALS),
    },
    include_tokens=False,
))

@admin_app.route('/admin/users', methods=['GET'])
def list_users():
    with base.lock:
        users_copy = list(USERS.values())
    return jsonify({"users": users_copy})

@admin_app.route('/admin/users', methods=['POST'])
def add_user():
    """Add a user at runtime (for seeding)."""
    data = request.get_json()
    username = data.get('samAccountName', '').lower()
    if username:
        with base.lock:
            USERS[username] = data
    return jsonify({"message": f"User {username} added"})

@admin_app.route('/admin/groups', methods=['GET'])
def list_groups():
    with base.lock:
        groups_copy = list(GROUPS.values())
    return jsonify({"groups": groups_copy})

@admin_app.route('/admin/groups', methods=['POST'])
def add_group():
    """Add a group at runtime (for seeding)."""
    data = request.get_json()
    name = data.get('name', '')
    if name:
        with base.lock:
            GROUPS[name] = data
    return jsonify({"message": f"Group {name} added"})

@admin_app.route('/admin/spns', methods=['GET'])
def list_spns():
    with base.lock:
        spns_copy = list(SERVICE_PRINCIPALS.values())
    return jsonify({"spns": spns_copy})

@admin_app.route('/admin/spns', methods=['POST'])
def add_spn():
    """Add an SPN at runtime (for seeding)."""
    data = request.get_json()
    spn = data.get('spn', '')
    if spn:
        with base.lock:
            SERVICE_PRINCIPALS[spn] = data
    return jsonify({"message": f"SPN {spn} added"})

@admin_app.route('/admin/computers', methods=['GET'])
def list_computers():
    with base.lock:
        computers_copy = list(COMPUTERS.values())
    return jsonify({"computers": computers_copy})

@admin_app.route('/admin/computers', methods=['POST'])
def add_computer():
    """Add a computer at runtime (for seeding)."""
    data = request.get_json()
    name = data.get('name', '')
    if name:
        with base.lock:
            COMPUTERS[name] = data
    return jsonify({"message": f"Computer {name} added"})


@admin_app.route('/admin/config', methods=['POST'])
def bulk_config():
    """Load complete domain controller configuration (for seeding).

    Accepts the domain_controller section from base_infrastructure.yaml.
    """
    data = request.get_json() or {}

    users_added = 0
    groups_added = 0
    spns_added = 0
    computers_added = 0

    with base.lock:
        # Load users
        for user in data.get('users', []):
            username = user.get('samAccountName', '').lower()
            if username:
                USERS[username] = user
                users_added += 1

        # Load groups
        for group in data.get('groups', []):
            name = group.get('name', '')
            if name:
                GROUPS[name] = group
                groups_added += 1

        # Load SPNs
        for spn_info in data.get('service_principal_names', []):
            spn = spn_info.get('spn', '')
            if spn:
                SERVICE_PRINCIPALS[spn] = spn_info
                spns_added += 1

        # Load computers
        for computer in data.get('computers', []):
            name = computer.get('name', '')
            if name:
                COMPUTERS[name] = computer
                computers_added += 1

    return jsonify({
        "message": "Configuration loaded",
        "users": users_added,
        "groups": groups_added,
        "spns": spns_added,
        "computers": computers_added,
    })


# ---------------------------------------------------------------------------
# Phase 2: DCSync, NTDS dump, account CRUD, SID history, password ops
# ---------------------------------------------------------------------------


@admin_app.route('/domain-logon', methods=['POST'])
def domain_logon():
    """Valid domain-account logon (T1078.002) on the reachable admin port.

    A successful domain authentication leaves a Kerberos TGT request (4768) and
    the resulting logon (4624) in the DC Security log (Sentinel SecurityEvent),
    plus the endpoint (MDE) view of the same logon (DeviceLogonEvents, the
    Defender artifact). All three ride the shared ``base`` buffer the collector
    polls on 8080. ``append_log`` stamps the AttackTechnique capture tag from the
    request header. The kerberos ``/as-req`` (port 88) handles the real ticket
    issuance; this admin-port endpoint is the capture-reachable equivalent.
    """
    data = request.get_json() or {}
    username = data.get('user', data.get('username', 'svc-backup'))
    domain_short = DOMAIN.split('.')[0]
    caller_ip = request.headers.get('X-Forwarded-For', request.remote_addr) or ""

    # 4768 — Kerberos TGT requested
    generate_security_event(4768, {
        "resultType": "Success",
        "eventData": {
            "TargetUserName": username, "TargetDomainName": domain_short,
            "ServiceName": "krbtgt", "Status": "0x0",
            "TicketEncryptionType": "0x12", "PreAuthType": "2",
            "IpAddress": f"::ffff:{caller_ip}",
        },
    })
    # 4624 — the successful logon that follows
    generate_security_event(4624, {
        "resultType": "Success",
        "eventData": {
            "TargetUserName": username, "TargetDomainName": domain_short,
            "LogonType": "3", "LogonProcessName": "Kerberos",
            "AuthenticationPackageName": "Kerberos",
            "WorkstationName": data.get("workstation", ""),
            "IpAddress": f"::ffff:{caller_ip}", "Status": "0x0",
        },
    })
    # DeviceLogonEvents — endpoint (MDE) view; routed by Type, AccountDomain marker
    base.append_log({
        "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "DeviceName": f"{DC_NAME}.{DOMAIN}",
        "ActionType": "LogonSuccess", "LogonType": "Network",
        "AccountName": username, "AccountDomain": domain_short,
        "RemoteIP": caller_ip, "Protocol": "Kerberos",
        "Type": "DeviceLogonEvents",
    })
    # IdentityLogonEvents — Defender-for-Identity view of the valid-account
    # logon (the base T1078 defender marker, LogonType Interactive). Routed by
    # Type; append_log stamps the AttackTechnique tag.
    base.append_log({
        "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "ActionType": "LogonSuccess", "LogonType": "Interactive",
        "AccountUpn": f"{username}@{DOMAIN}",
        "AccountDisplayName": username,
        "Application": "Active Directory", "Protocol": "Kerberos",
        "IPAddress": caller_ip,
        "Type": "IdentityLogonEvents",
    })

    return jsonify({"status": "logon_success", "user": username, "domain": domain_short})


@admin_app.route('/recon', methods=['POST'])
def admin_recon():
    """Domain account/group enumeration (T1087.002) on the reachable admin port.

    The ldap_app ``/recon`` (port 389) is not reachable via ${DOMAIN_CONTROLLER}
    (=8080). This admin-port equivalent emits the host-side DeviceProcessEvents
    process artifact for each enumeration command (the T1087.002 Defender marker,
    ProcessCommandLine ~ "net user") plus the 4661 directory-access SecurityEvent.
    """
    data = request.get_json() or {}
    commands = data.get('commands', ["whoami /all", "net user /domain",
                                     "net group \"Domain Admins\" /domain"])
    source_host = data.get('source_host', 'unknown')
    source_user = data.get('source_user', 'anonymous')

    # 4661 — directory object enumeration (Sentinel SecurityEvent).
    generate_security_event(4661, {
        "resultType": "Success",
        "eventData": {
            "SubjectUserName": source_user,
            "SubjectDomainName": DOMAIN.split('.')[0],
            "ObjectServer": "DS", "ObjectType": "SAM_DOMAIN",
            "ObjectName": DOMAIN, "AccessMask": "0x211b",
            "SourceHost": source_host, "Commands": commands,
        },
    })

    # DeviceProcessEvents — the host-side process artifact of each command
    # (T1087.002 Defender marker). Runs on the compromised host; the DC is the
    # capture-reachable proxy. append_log stamps the AttackTechnique tag.
    for cmd in commands:
        base.append_log({
            "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "DeviceName": source_host, "ActionType": "ProcessCreated",
            "FileName": cmd.split()[0] if cmd else "cmd.exe",
            "ProcessCommandLine": cmd,
            "AccountName": source_user, "AccountDomain": DOMAIN.split('.')[0],
            "InitiatingProcessFileName": "cmd.exe",
            "Type": "DeviceProcessEvents",
        })

    return jsonify({"status": "recon_complete", "commands": commands})


@admin_app.route('/kerberoast', methods=['POST'])
def admin_kerberoast():
    """Kerberoasting (T1558.003) on the reachable admin port.

    The kerberos_app ``/tgs-req`` (port 88) is NOT reachable via
    ${DOMAIN_CONTROLLER} (=8080). This admin-port equivalent emits the 4769
    service-ticket-request SecurityEvent with RC4 (0x17) encryption — the
    Kerberoasting Sentinel marker — for each requested SPN. append_log stamps
    the AttackTechnique tag.
    """
    data = request.get_json() or {}
    spn = data.get('servicePrincipal') or data.get('spn') or 'MSSQLSvc/sql01:1433'
    spns = data.get('servicePrincipals') or [spn]
    source_user = data.get('source_user') or data.get('user', 'anonymous')
    caller_ip = request.remote_addr or '0.0.0.0'

    for s in spns:
        generate_security_event(4769, {
            "resultType": "Success",
            "eventData": {
                "TargetUserName": source_user,
                "TargetDomainName": DOMAIN.split('.')[0],
                "ServiceName": s.split('/')[0] if '/' in s else s,
                "ServiceSid": "S-1-0-0",
                "TicketOptions": "0x40810000",
                "Status": "0x0",
                "TicketEncryptionType": "0x17",  # RC4 — Kerberoasting indicator
                "IpAddress": f"::ffff:{caller_ip}",
                "IpPort": str(random.randint(49152, 65535)),
                "TransmittedServices": "-",
            },
        })

    return jsonify({"status": "kerberoast_complete", "spns": spns})


@admin_app.route('/password-spray', methods=['POST'])
def admin_password_spray():
    """On-prem password spray (T1110.003) on the reachable admin port.

    The ldap_app ``/bind`` (port 389) is not reachable via ${DOMAIN_CONTROLLER}
    (=8080). This admin-port equivalent emits the SecurityEvent 4625 failed-logon
    burst across many accounts from one source IP (the on-prem spray Sentinel
    marker) plus a single 4624 success for the cracked account. append_log stamps
    the AttackTechnique tag.
    """
    data = request.get_json() or {}
    targets = data.get('targets') or data.get('target_users') or list(USERS.keys())[:6]
    if isinstance(targets, str):
        targets = [targets]
    source_ip = data.get('source_ip') or request.remote_addr or '0.0.0.0'
    success_user = data.get('success_user')

    for u in targets:
        generate_security_event(4625, {
            "resultType": "Failure",
            "eventData": {
                "SubjectUserName": "-", "SubjectDomainName": "-",
                "TargetUserName": u, "TargetDomainName": DOMAIN.split('.')[0],
                "LogonType": 3,
                "Status": "0xc000006d", "SubStatus": "0xc000006a",
                "FailureReason": "Unknown user name or bad password",
                "IpAddress": source_ip,
                "IpPort": str(random.randint(49152, 65535)),
            },
        })

    if success_user:
        generate_security_event(4624, {
            "resultType": "Success",
            "eventData": {
                "SubjectUserName": "-", "SubjectDomainName": "-",
                "TargetUserName": success_user,
                "TargetDomainName": DOMAIN.split('.')[0],
                "LogonType": 3, "AuthenticationPackageName": "NTLM",
                "IpAddress": source_ip,
                "IpPort": str(random.randint(49152, 65535)),
            },
        })

    return jsonify({"status": "spray_complete", "attempted": len(targets),
                    "success_user": success_user})


@admin_app.route('/dcsync', methods=['POST'])
def dcsync():
    """DCSync replication request — mimics DsGetNcChanges RPC.

    Returns credential data for the target account.  This is the technique
    used by mimikatz ``lsadump::dcsync`` to replicate AD password data.
    """
    data = request.get_json() or {}
    source_host = data.get('source_host', 'unknown')
    source_user = data.get('source_user', 'unknown')
    target_user = data.get('target_user', '') or 'krbtgt'
    tool = data.get('tool', 'unknown')

    with base.lock:
        user = USERS.get(target_user.lower())

    # DCSync replicates whatever account is named; if the target isn't a seeded
    # user, still model the replication (a real DCSync of an arbitrary principal
    # leaves the same 4662 / IdentityDirectoryEvents telemetry).
    if not user:
        user = {"sid": "S-1-5-21-0-0-0-500"}

    # Generate a mock NTLM hash for the target
    nt_hash = secrets.token_hex(16)
    result = {
        "target_user": target_user,
        "ntlm_hash": f"aad3b435b51404eeaad3b435b51404ee:{nt_hash}",
        "lm_hash": "aad3b435b51404eeaad3b435b51404ee",
        "sid": user.get('sid', 'S-1-5-21-0-0-0-0'),
        "password_last_set": (datetime.now(timezone.utc) - timedelta(days=random.randint(1, 90))).isoformat(),
    }

    with base.lock:
        REPLICATION_LOG.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_host": source_host,
            "source_user": source_user,
            "target_user": target_user,
            "tool": tool,
        })

    # Event 4662 — DsGetNcChanges replication rights
    generate_security_event(4662, {
        "resultType": "Success",
        "eventData": {
            "SubjectUserName": source_user,
            "SubjectDomainName": DOMAIN.split('.')[0],
            "ObjectServer": "DS",
            "ObjectType": "domainDNS",
            "ObjectName": f"DC={DOMAIN.replace('.', ',DC=')}",
            "OperationType": "Object Access",
            "AccessMask": "0x100",
            "Properties": "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}",  # DS-Replication-Get-Changes
            "SourceHost": source_host,
            "_event_type": "dcsync",
            "_alert": "dcsync",
        }
    })

    # Defender for Identity view: a directory replication request
    # (IdentityDirectoryEvents ActionType=Replication — the T1003.006 defender
    # marker). Type routes it to its table; append_log stamps the AttackTechnique.
    base.append_log({
        "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "ActionType": "Replication",
        "TargetAccountUpn": target_user,
        "TargetDeviceName": f"{DC_NAME}.{DOMAIN}",
        "AccountName": source_user,
        "AccountDomain": DOMAIN.split('.')[0],
        "AdditionalFields": json.dumps({"Operation": "DsGetNcChanges"}),
        "Type": "IdentityDirectoryEvents",
    })

    return jsonify(result)


@admin_app.route('/ntds/dump', methods=['POST'])
def ntds_dump():
    """NTDS.dit exfiltration via ntdsutil or volume shadow copy.

    Returns a mock credential database for all domain accounts.
    """
    data = request.get_json() or {}
    method = data.get('method', 'ntdsutil')
    source_host = data.get('source_host', 'unknown')
    source_user = data.get('source_user', 'unknown')

    credentials = []
    with base.lock:
        for uname, user in USERS.items():
            credentials.append({
                "username": user.get('samAccountName', uname),
                "sid": user.get('sid', ''),
                "ntlm_hash": f"aad3b435b51404eeaad3b435b51404ee:{secrets.token_hex(16)}",
                "enabled": user.get('enabled', True),
            })

    # Log process event for ntdsutil.exe (DeviceProcessEvents — the T1003.003
    # defender marker; Type routes it to the right table).
    base.append_log({
        "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + "000Z",
        "DeviceName": f"{DC_NAME}.{DOMAIN}",
        "ActionType": "ProcessCreated",
        "FileName": "ntdsutil.exe" if method == "ntdsutil" else "vssadmin.exe",
        "ProcessCommandLine": f"{method} \"activate instance ntds\" \"ifm\" \"create full c:\\temp\\ntds\"",
        "AccountName": source_user,
        "AccountDomain": DOMAIN.split('.')[0],
        "_event_type": "ntds_dump",
        "_source": "domain_controller",
        "Type": "DeviceProcessEvents",
    })

    # SecurityEvent 4662 — directory-services access for the NTDS extraction
    # (the Sentinel marker for T1003.003).
    generate_security_event(4662, {
        "resultType": "Success",
        "eventData": {
            "SubjectUserName": source_user,
            "SubjectDomainName": DOMAIN.split('.')[0],
            "ObjectServer": "DS", "ObjectType": "domainDNS",
            "ObjectName": f"DC={DOMAIN.replace('.', ',DC=')}",
            "OperationType": "Object Access", "AccessMask": "0x100",
            "SourceHost": source_host,
            "_event_type": "ntds_dump",
        },
    })

    # Log file event for NTDS.dit copy
    base.append_log({
        "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + "000Z",
        "DeviceName": f"{DC_NAME}.{DOMAIN}",
        "ActionType": "FileCreated",
        "FileName": "ntds.dit",
        "FolderPath": "C:\\temp\\ntds\\Active Directory",
        "FileSize": len(credentials) * 1024,
        "_event_type": "ntds_dump",
        "_source": "domain_controller",
        "Type": "DeviceFileEvents",
    })

    return jsonify({
        "method": method,
        "credentials": credentials,
        "count": len(credentials),
    })


@admin_app.route('/accounts', methods=['POST'])
def create_account():
    """Create a new domain account.

    Optionally adds the account to groups (e.g., Domain Admins for
    backdoor persistence).
    """
    data = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')
    source_host = data.get('source_host', 'unknown')
    source_user = data.get('source_user', 'unknown')
    groups = data.get('groups', ['Domain Users'])

    if not username:
        return jsonify({"error": "username required"}), 400

    sid = f"S-1-5-21-3623811015-3361044348-30300820-{random.randint(2000, 9999)}"

    new_user = {
        "samAccountName": username,
        "sid": sid,
        "memberOf": groups,
        "enabled": True,
        "created_by": source_user,
        "created_from": source_host,
    }

    with base.lock:
        USERS[username.lower()] = new_user
        # Add to groups
        for group_name in groups:
            if group_name in GROUPS:
                members = GROUPS[group_name].get('members', [])
                if username not in members:
                    members.append(username)
                    GROUPS[group_name]['members'] = members

    # Event 4720 — User account created
    generate_security_event(4720, {
        "resultType": "Success",
        "eventData": {
            "TargetUserName": username,
            "TargetDomainName": DOMAIN.split('.')[0],
            "TargetSid": sid,
            "SubjectUserName": source_user,
            "SubjectDomainName": DOMAIN.split('.')[0],
            "SourceHost": source_host,
        }
    })

    # Event 4728 for each group addition
    for group_name in groups:
        generate_security_event(4728, {
            "resultType": "Success",
            "eventData": {
                "MemberName": f"CN={username},CN=Users,DC={DOMAIN.replace('.', ',DC=')}",
                "MemberSid": sid,
                "TargetUserName": group_name,
                "TargetDomainName": DOMAIN.split('.')[0],
                "SubjectUserName": source_user,
                "SubjectDomainName": DOMAIN.split('.')[0],
                "SourceHost": source_host,
            }
        })

    return jsonify({"username": username, "sid": sid, "groups": groups}), 201


@admin_app.route('/accounts/<username>/sid-history', methods=['PUT'])
def add_sid_history(username):
    """Inject SID history — privilege escalation technique.

    Adding the Domain Admins SID (S-1-5-32-544) to a user's SID history
    gives them admin privileges without being in the group.
    """
    data = request.get_json() or {}
    sid = data.get('sid', '')
    source_user = data.get('source_user', 'unknown')

    with base.lock:
        user = USERS.get(username.lower())
    if not user:
        return jsonify({"error": f"User '{username}' not found"}), 404

    with base.lock:
        SID_HISTORY.setdefault(username.lower(), []).append(sid)

    # Event 4765 — SID history added
    generate_security_event(4765, {
        "resultType": "Success",
        "eventData": {
            "TargetUserName": username,
            "TargetDomainName": DOMAIN.split('.')[0],
            "SidHistory": sid,
            "SubjectUserName": source_user,
            "SubjectDomainName": DOMAIN.split('.')[0],
            "_alert": "sid_history_injection",
        }
    })

    return jsonify({"username": username, "sid_history": SID_HISTORY.get(username.lower(), [])})


@admin_app.route('/accounts/<username>/password', methods=['PUT'])
def change_password(username):
    """Password change or password spray.

    If ``spray=true``, simulates a failed logon attempt (Event 4625).
    Otherwise, simulates a successful password reset (Event 4724).
    """
    data = request.get_json() or {}
    new_password = data.get('new_password', '')
    source_user = data.get('source_user', 'unknown')
    spray = data.get('spray', False)

    caller_ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    with base.lock:
        user = USERS.get(username.lower())

    if spray:
        # Password spray — Event 4625 (failed logon)
        generate_security_event(4625, {
            "resultType": "Failure",
            "eventData": {
                "TargetUserName": username,
                "TargetDomainName": DOMAIN.split('.')[0],
                "LogonType": 3,
                "Status": "0xc000006d",
                "SubStatus": "0xc000006a" if user else "0xc0000064",
                "FailureReason": "Unknown user name or bad password",
                "IpAddress": caller_ip,
                "_event_type": "password_spray",
            }
        })
        return jsonify({"result": "failed", "reason": "invalid_credentials"}), 401

    if not user:
        return jsonify({"error": f"User '{username}' not found"}), 404

    # Event 4724 — Password reset
    generate_security_event(4724, {
        "resultType": "Success",
        "eventData": {
            "TargetUserName": username,
            "TargetDomainName": DOMAIN.split('.')[0],
            "SubjectUserName": source_user,
            "SubjectDomainName": DOMAIN.split('.')[0],
        }
    })

    return jsonify({"username": username, "password_changed": True})


# ============================================================================
# Background Activity Simulation
# ============================================================================

def generate_benign_activity():
    """Generate periodic benign DC activity."""
    while True:
        time.sleep(random.randint(10, 30))

        # Simulate random benign activities
        activity_type = random.choice(['logon', 'ldap_query', 'tgt_request', 'service_ticket'])

        if activity_type == 'logon' and USERS:
            user = random.choice(list(USERS.keys()))
            generate_security_event(4624, {
                "resultType": "Success",
                "eventData": {
                    "TargetUserName": user,
                    "TargetDomainName": DOMAIN.split('.')[0],
                    "LogonType": random.choice([2, 3, 10]),  # Interactive, Network, RemoteInteractive
                    "IpAddress": f"172.30.10.{random.randint(30, 50)}",
                    "LogonProcessName": "Kerberos",
                    "AuthenticationPackageName": "Kerberos",
                }
            })

        elif activity_type == 'tgt_request' and USERS:
            user = random.choice(list(USERS.keys()))
            generate_security_event(4768, {
                "resultType": "Success",
                "eventData": {
                    "TargetUserName": user,
                    "TargetDomainName": DOMAIN.split('.')[0],
                    "ServiceName": "krbtgt",
                    "Status": "0x0",
                    "IpAddress": f"::ffff:172.30.10.{random.randint(30, 50)}",
                    "TicketEncryptionType": "0x12",
                }
            })

        elif activity_type == 'service_ticket' and USERS and SERVICE_PRINCIPALS:
            user = random.choice(list(USERS.keys()))
            spn_info = random.choice(list(SERVICE_PRINCIPALS.values()))
            generate_security_event(4769, {
                "resultType": "Success",
                "eventData": {
                    "TargetUserName": user,
                    "TargetDomainName": DOMAIN.split('.')[0],
                    "ServiceName": spn_info['spn'].split('/')[0] if '/' in spn_info['spn'] else spn_info['spn'],
                    "ServiceSid": spn_info.get('sid', 'S-1-0-0'),
                    "Status": "0x0",
                    "IpAddress": f"::ffff:172.30.10.{random.randint(30, 50)}",
                    "TicketEncryptionType": "0x12",
                }
            })

        elif activity_type == 'ldap_query':
            generate_security_event(4662, {
                "resultType": "Success",
                "eventData": {
                    "SubjectUserName": random.choice(list(USERS.keys())) if USERS else "system",
                    "SubjectDomainName": DOMAIN.split('.')[0],
                    "ObjectServer": "DS",
                    "ObjectType": "(%{bf967aba-0de6-11d0-a285-00aa003049e2})",
                    "ObjectName": f"DC={DOMAIN.replace('.', ',DC=')}",
                    "OperationType": "Object Access",
                    "AccessMask": "0x100",
                    "IpAddress": f"172.30.10.{random.randint(30, 50)}",
                }
            })

# ============================================================================
# Initialization
# ============================================================================

def load_config():
    global CONFIG, USERS, GROUPS, SERVICE_PRINCIPALS, COMPUTERS

    try:
        with open(CONFIG_PATH, 'r') as f:
            CONFIG = yaml.safe_load(f) or {}
    except Exception as e:
        print(f"[DomainController] Could not load config: {e}")
        CONFIG = {}

    # Load domain controller config
    dc_config = CONFIG.get('domain_controller', {})

    # Initialize users
    for user in dc_config.get('users', DEFAULT_USERS):
        USERS[user['samAccountName'].lower()] = user

    # Initialize groups
    for group in dc_config.get('groups', DEFAULT_GROUPS):
        GROUPS[group['name']] = group

    # Initialize SPNs
    for spn in dc_config.get('service_principal_names', DEFAULT_SPNS):
        SERVICE_PRINCIPALS[spn['spn']] = spn

    # Initialize computers
    for computer in dc_config.get('computers', DEFAULT_COMPUTERS):
        COMPUTERS[computer['name']] = computer

    print(f"[DomainController] Loaded {len(USERS)} users, {len(GROUPS)} groups, {len(SERVICE_PRINCIPALS)} SPNs, {len(COMPUTERS)} computers")

def run_servers():
    """Run all three servers in separate threads."""
    load_config()

    # Start background activity
    bg_thread = threading.Thread(target=generate_benign_activity, daemon=True)
    bg_thread.start()

    # LDAP server (port 389)
    ldap_thread = threading.Thread(
        target=lambda: ldap_app.run(host='0.0.0.0', port=389, threaded=True, use_reloader=False),
        daemon=True
    )
    ldap_thread.start()

    # Kerberos server (port 88)
    kerberos_thread = threading.Thread(
        target=lambda: kerberos_app.run(host='0.0.0.0', port=88, threaded=True, use_reloader=False),
        daemon=True
    )
    kerberos_thread.start()

    # Admin/Audit server (port 8080) - runs in main thread
    print(f"[DomainController] Starting - Domain: {DOMAIN}, DC: {DC_NAME}")
    print(f"[DomainController] LDAP on :389, Kerberos on :88, Admin on :8080")
    admin_app.run(host='0.0.0.0', port=8080, use_reloader=False)

if __name__ == '__main__':
    run_servers()
