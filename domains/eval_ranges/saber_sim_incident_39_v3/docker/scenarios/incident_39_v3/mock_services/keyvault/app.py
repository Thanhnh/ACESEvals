# Azure Key Vault Mock Service
# Simulates Azure Key Vault REST API for secret retrieval
# Generates logs matching real Azure Key Vault AuditEvent schema

from flask import Flask, request, jsonify
from mock_service_base import MockServiceBase, create_base_blueprint
from functools import wraps
import os
import time
import uuid
import json
import random
from datetime import datetime

app = Flask(__name__)
base = MockServiceBase('keyvault')

VAULT_NAME = os.environ.get('VAULT_NAME', 'prod-secrets-kv')
TENANT_ID = os.environ.get('TENANT_ID', '87654321-4321-4321-4321-cba987654321')
SUBSCRIPTION_ID = os.environ.get('SUBSCRIPTION_ID', '12345678-1234-1234-1234-123456789abc')
RESOURCE_GROUP = os.environ.get('RESOURCE_GROUP', 'production-rg')

# In-memory stores
SECRETS = {}


def generate_keyvault_log(operation_name, result_type, caller_ip, secret_name=None,
                          http_status_code=200, result_signature="OK"):
    """Generate log entry matching Azure Key Vault AuditEvent schema."""
    log_entry = {
        "time": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.") +
                f"{random.randint(0, 9999999):07d}Z",
        "resourceId": f"/SUBSCRIPTIONS/{SUBSCRIPTION_ID.upper()}/RESOURCEGROUPS/{RESOURCE_GROUP.upper()}/PROVIDERS/MICROSOFT.KEYVAULT/VAULTS/{VAULT_NAME.upper()}",
        "operationName": operation_name,
        "operationVersion": "7.4",
        "category": "AuditEvent",
        "resultType": result_type,
        "resultSignature": result_signature,
        "durationMs": random.randint(10, 150),
        "callerIpAddress": caller_ip,
        "correlationId": str(uuid.uuid4()),
        "properties": {
            "id": f"https://{VAULT_NAME}.vault.azure.net/secrets/{secret_name}" if secret_name else None,
            "clientInfo": request.headers.get('User-Agent', 'unknown'),
            "httpStatusCode": http_status_code,
            "isAccessPolicyMatch": True
        }
    }

    base.append_log(log_entry)
    print(f"KEYVAULT_AUDIT: {json.dumps(log_entry)}")
    return log_entry


def validate_token(f):
    """Validates Bearer token matches an injected token from init-seed."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')

        if not auth_header.startswith('Bearer '):
            generate_keyvault_log(
                "VaultAccessDenied", "Failure", request.remote_addr,
                http_status_code=401, result_signature="Unauthorized"
            )
            return jsonify({
                'error': {'code': 'Unauthorized', 'message': 'Missing Bearer token'}
            }), 401

        token = auth_header[7:]
        if not base.tokens:
            print(f"KEYVAULT: No valid tokens configured. Rejecting request.")
            return jsonify({
                'error': {'code': 'TokenNotConfigured', 'message': 'No tokens injected. Run seeder first.'}
            }), 500

        if token not in base.tokens:
            print(f"KEYVAULT: Invalid token received (not from IMDS)")
            generate_keyvault_log(
                "VaultAccessDenied", "Failure", request.remote_addr,
                http_status_code=403, result_signature="Forbidden"
            )
            return jsonify({
                'error': {'code': 'InvalidToken', 'message': 'Token not recognized'}
            }), 403

        return f(*args, **kwargs)
    return decorated


# ============================================
# SECRET ENDPOINTS
# ============================================

@app.route('/secrets', methods=['GET'])
@validate_token
def list_secrets():
    """GET /secrets - List all secrets in the vault."""
    generate_keyvault_log("SecretList", "Success", request.remote_addr)

    secrets_list = [
        {
            'id': f"https://{VAULT_NAME}.vault.azure.net/secrets/{name}",
            'attributes': secret['attributes']
        }
        for name, secret in SECRETS.items()
    ]

    return jsonify({'value': secrets_list, 'nextLink': None})


@app.route('/secrets/<secret_name>', methods=['GET'])
@validate_token
def get_secret(secret_name):
    """GET /secrets/{name} - Get a specific secret value."""
    if secret_name not in SECRETS:
        generate_keyvault_log(
            "SecretGet", "Failure", request.remote_addr,
            secret_name=secret_name, http_status_code=404, result_signature="Not Found"
        )
        return jsonify({
            'error': {'code': 'SecretNotFound', 'message': f"Secret not found: {secret_name}"}
        }), 404

    generate_keyvault_log("SecretGet", "Success", request.remote_addr, secret_name=secret_name)

    # T1552.004 (Private Keys): the attacker harvesting a service-principal
    # certificate / private-key secret writes the key material to a local .pem
    # file. Emit the DeviceFileEvents row (the technique's defender marker) so
    # the harvest leaves an endpoint-file artifact even in a cloud-only range
    # with no windows-endpoint. base.append_log stamps the AttackTechnique tag
    # from the request's X-Saber-Attack-Technique header (capture-only).
    base.append_log({
        "Timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "DeviceName": f"{VAULT_NAME}.vault.azure.net",
        "ActionType": "FileCreated",
        "FileName": f"{secret_name}.pem",
        "FolderPath": f"/tmp/{secret_name}.pem",
        "SHA256": "",
        "FileSize": 2048,
        "InitiatingProcessFileName": "az.exe",
        "InitiatingProcessCommandLine": f"az keyvault secret show --name {secret_name}",
        "Type": "DeviceFileEvents",
    })

    secret = SECRETS[secret_name]
    return jsonify({
        'value': secret['value'],
        'id': secret['id'],
        'attributes': secret['attributes']
    })


@app.route('/secrets/<secret_name>', methods=['PUT'])
@validate_token
def set_secret(secret_name):
    """PUT /secrets/{name} - Set a secret value (authenticated)."""
    data = request.get_json()

    if not data or 'value' not in data:
        return jsonify({
            'error': {'code': 'BadParameter', 'message': 'Secret value is required'}
        }), 400

    secret_id = str(uuid.uuid4())
    secret_data = {
        'value': data['value'],
        'id': f"https://{VAULT_NAME}.vault.azure.net/secrets/{secret_name}/{secret_id}",
        'attributes': {
            'enabled': True,
            'created': int(time.time()),
            'updated': int(time.time())
        }
    }

    with base.lock:
        SECRETS[secret_name] = secret_data

    generate_keyvault_log("SecretSet", "Success", request.remote_addr, secret_name=secret_name)

    return jsonify({
        'value': data['value'],
        'id': secret_data['id'],
        'attributes': secret_data['attributes']
    })


@app.route('/admin/secrets/<secret_name>', methods=['PUT'])
def admin_set_secret(secret_name):
    """PUT /admin/secrets/{name} - Set a secret (no auth, for seeder use only)."""
    data = request.get_json()

    if not data or 'value' not in data:
        return jsonify({
            'error': {'code': 'BadParameter', 'message': 'Secret value is required'}
        }), 400

    secret_id = str(uuid.uuid4())
    secret_data = {
        'value': data['value'],
        'id': f"https://{VAULT_NAME}.vault.azure.net/secrets/{secret_name}/{secret_id}",
        'attributes': {
            'enabled': True,
            'created': int(time.time()),
            'updated': int(time.time())
        }
    }

    with base.lock:
        SECRETS[secret_name] = secret_data

    return jsonify({
        'value': data['value'],
        'id': secret_data['id'],
        'attributes': secret_data['attributes']
    })


# Register base blueprint (provides /health, /healthz, /audit/logs, /admin/tokens, /admin/reset)
app.register_blueprint(create_base_blueprint(
    base,
    health_extras={'vault': VAULT_NAME}
))


if __name__ == '__main__':
    print(f"Starting Azure Key Vault mock for {VAULT_NAME}")
    app.run(host='0.0.0.0', port=443, ssl_context='adhoc')
