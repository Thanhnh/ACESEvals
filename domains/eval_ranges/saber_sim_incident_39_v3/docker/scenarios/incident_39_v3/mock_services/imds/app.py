# Azure Instance Metadata Service (IMDS) Mock
# Simulates http://169.254.169.254/metadata/
# Generates synthetic IMDS access logs for detection
# Note: Real Azure doesn't externally log IMDS access - this is for simulation

from flask import Flask, request, jsonify
import os
import time
import uuid
import json
import random
from datetime import datetime
from mock_service_base import MockServiceBase, create_base_blueprint

app = Flask(__name__)
base = MockServiceBase('imds')

SUBSCRIPTION_ID = os.environ.get('SUBSCRIPTION_ID', '12345678-1234-1234-1234-123456789abc')
RESOURCE_GROUP = os.environ.get('RESOURCE_GROUP', 'production-rg')
VM_NAME = os.environ.get('VM_NAME', 'webapp-vm-001')

# Custom tokens injected via /admin/tokens endpoint
# Maps token_name -> token_value (e.g., "managed_identity" -> "eyJ...")
CUSTOM_TOKENS = {}


def generate_imds_access_log(endpoint, ip_address, resource=None, success=True):
    """
    Generate synthetic IMDS access log for credential theft detection.
    Schema follows azure_log_schemas.yaml imds_access_log definition.

    Note: In real Azure, IMDS access isn't logged externally. These logs are
    synthetic for threat hunting simulation. Format inspired by Azure Activity logs.
    """
    log_entry = {
        "time": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.") +
                f"{random.randint(0, 9999999):07d}Z",
        "resourceId": f"/SUBSCRIPTIONS/{SUBSCRIPTION_ID.upper()}/RESOURCEGROUPS/{RESOURCE_GROUP.upper()}/PROVIDERS/MICROSOFT.COMPUTE/VIRTUALMACHINES/{VM_NAME.upper()}",
        "operationName": "IMDS.GetToken",
        "category": "InstanceMetadata",
        "resultType": "Success" if success else "Failure",
        "callerIpAddress": ip_address,
        "correlationId": str(uuid.uuid4()),
        "properties": {
            "endpoint": endpoint,
            "resource": resource,
            "vmName": VM_NAME,
            "clientId": "11111111-2222-3333-4444-555555555555",
            "userAgent": request.headers.get('User-Agent', 'unknown')
        }
    }

    base.append_log(log_entry)
    print(f"IMDS_AUDIT: {json.dumps(log_entry)}")
    return log_entry


def require_metadata_header(f):
    """Azure IMDS requires Metadata: true header"""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.headers.get('Metadata', '').lower() != 'true':
            return jsonify({
                'error': 'Bad Request',
                'message': 'Required metadata header not specified'
            }), 400
        return f(*args, **kwargs)
    return decorated

# ============================================
# MANAGED IDENTITY TOKEN ENDPOINT
# ============================================

@app.route('/metadata/identity/oauth2/token', methods=['GET'])
def get_managed_identity_token():
    """
    GET http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

    This is the CRITICAL endpoint for credential theft attacks!

    Supports multiple identity selection for VMs with multiple managed identities:
    - client_id: Select identity by client (application) ID
    - object_id: Select identity by object (principal) ID
    - msi_res_id: Select identity by Azure resource ID

    If custom tokens are set via /admin/tokens, returns those instead of generating.
    """
    resource = request.args.get('resource', 'https://management.azure.com/')
    client_id = request.args.get('client_id', None)
    object_id = request.args.get('object_id', None)
    msi_res_id = request.args.get('msi_res_id', None)

    # Log identity selector used (important for detecting targeted identity theft)
    identity_selector = 'system-assigned'
    if client_id:
        identity_selector = f'client_id:{client_id}'
    elif object_id:
        identity_selector = f'object_id:{object_id}'
    elif msi_res_id:
        identity_selector = f'msi_res_id:{msi_res_id}'

    generate_imds_access_log(
        f'/metadata/identity/oauth2/token?resource={resource}&identity={identity_selector}',
        request.remote_addr,
        resource=resource
    )

    now = int(time.time())

    # Check if custom token was injected via /admin/tokens
    # Try resource-specific token first, then fall back to "managed_identity"
    custom_token = CUSTOM_TOKENS.get(resource) or CUSTOM_TOKENS.get('managed_identity')
    if custom_token:
        print(f"IMDS: Returning custom token for resource={resource}")
        return jsonify({
            'access_token': custom_token,
            'client_id': client_id or '11111111-2222-3333-4444-555555555555',
            'expires_in': '3599',
            'expires_on': str(now + 3599),
            'ext_expires_in': '3599',
            'not_before': str(now),
            'resource': resource,
            'token_type': 'Bearer'
        })

    # No token injected - return 403 (no managed identity configured)
    print(f"IMDS: No token configured for resource={resource}")
    return jsonify({
        'error': 'managed_identity_not_configured',
        'message': f'No managed identity token available for resource={resource}. '
                   f'POST to /admin/tokens to inject tokens.'
    }), 403

# ============================================
# ADMIN & AUDIT ENDPOINTS
# ============================================

@app.route('/admin/tokens', methods=['GET', 'POST', 'DELETE'])
def admin_tokens():
    """
    Manage custom tokens that IMDS will return.

    POST: Inject custom tokens
      Body: {"tokens": {"managed_identity": "eyJ...", "keyvault": "eyJ..."}}

    GET: List current custom tokens

    DELETE: Clear all custom tokens

    When custom tokens are set, get_managed_identity_token will return
    the "managed_identity" token instead of generating one dynamically.
    """
    global CUSTOM_TOKENS

    if request.method == 'POST':
        data = request.get_json() or {}
        tokens = data.get('tokens', {})
        CUSTOM_TOKENS.update(tokens)
        print(f"IMDS_ADMIN: Injected {len(tokens)} custom token(s)")
        return jsonify({
            "status": "ok",
            "tokens_set": list(CUSTOM_TOKENS.keys())
        })

    elif request.method == 'DELETE':
        count = len(CUSTOM_TOKENS)
        CUSTOM_TOKENS.clear()
        print(f"IMDS_ADMIN: Cleared {count} custom token(s)")
        return jsonify({"status": "ok", "cleared": count})

    else:  # GET
        return jsonify({
            "tokens": list(CUSTOM_TOKENS.keys()),
            "count": len(CUSTOM_TOKENS)
        })


# Register base blueprint (provides /health, /healthz, /audit/logs, /admin/reset)
app.register_blueprint(create_base_blueprint(
    base,
    health_extras={'vm': VM_NAME},
    include_tokens=False,
))

if __name__ == '__main__':
    print(f"Starting Azure IMDS mock for {VM_NAME}")
    print(f"Subscription: {SUBSCRIPTION_ID}")
    app.run(host='0.0.0.0', port=80)
