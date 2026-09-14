# Mock Azure Functions Runtime
# Simulates function app for lateral movement / credential extraction

from flask import Flask, request, jsonify
from mock_service_base import MockServiceBase, create_base_blueprint
from functools import wraps
import os
import time
from datetime import datetime
import json

app = Flask(__name__)
base = MockServiceBase('azure-functions')

FUNCTION_APP_NAME = os.environ.get('FUNCTION_APP_NAME', 'prod-data-processor')

# Simulated function definitions (metadata only)
FUNCTIONS = {
    'BlobProcessor': {
        'name': 'BlobProcessor',
        'trigger': 'blobTrigger',
        'status': 'Running'
    },
    'HttpEndpoint': {
        'name': 'HttpEndpoint',
        'trigger': 'httpTrigger',
        'status': 'Running'
    }
}


def log_access(operation, details, ip_address):
    """Generate log entry matching Azure FunctionAppLogs schema from azure_log_schemas.yaml."""
    import uuid
    import random
    log_entry = {
        'time': datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.") + f"{random.randint(0, 9999999):07d}Z",
        'resourceId': f"/SUBSCRIPTIONS/12345678-1234-1234-1234-123456789ABC/RESOURCEGROUPS/PRODUCTION-RG/PROVIDERS/MICROSOFT.WEB/SITES/{FUNCTION_APP_NAME.upper()}",
        'operationName': operation,
        'category': 'FunctionAppLogs',
        'resultType': 'Success',
        'durationMs': random.randint(50, 500),
        'callerIpAddress': ip_address,
        'correlationId': str(uuid.uuid4()),
        'properties': details
    }
    base.append_log(log_entry)
    print(f"FUNCTION_AUDIT: {json.dumps(log_entry)}")


def validate_token(f):
    """Validates Bearer token matches an injected token from init-seed."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': {'code': 'AuthenticationFailed', 'message': 'Missing Bearer token'}}), 401

        token = auth_header[7:]  # Strip "Bearer "
        if not base.tokens:
            print(f"FUNCTIONS: No valid tokens configured. Rejecting request.")
            return jsonify({'error': {'code': 'TokenNotConfigured', 'message': 'No tokens injected. Run seeder first.'}}), 500

        if token not in base.tokens:
            print(f"FUNCTIONS: Invalid token received (not from IMDS)")
            return jsonify({'error': {'code': 'InvalidToken', 'message': 'Token not recognized'}}), 403

        return f(*args, **kwargs)
    return decorated


# ============================================
# ADMIN API - Kudu-like endpoints
# ============================================

@app.route('/admin/functions', methods=['GET'])
@validate_token
def list_functions():
    """List all functions in this function app."""
    log_access('Admin.ListFunctions', {'functionApp': FUNCTION_APP_NAME}, request.remote_addr)

    return jsonify({
        'value': [
            {'name': name, 'trigger': func['trigger'], 'status': func['status']}
            for name, func in FUNCTIONS.items()
        ]
    })


@app.route('/admin/host/keys', methods=['GET'])
@validate_token
def get_host_keys():
    """Get host keys - HIGH VALUE credential extraction target."""
    log_access('Admin.GetHostKeys', {'functionApp': FUNCTION_APP_NAME}, request.remote_addr)

    return jsonify({
        'masterKey': f'mock-master-key-{int(time.time())}',
        'functionKeys': {
            'default': f'mock-host-function-key-{int(time.time())}'
        },
        'systemKeys': {}
    })


# ============================================
# VFS - Credential Leak via local.settings.json
# ============================================

@app.route('/api/vfs/local.settings.json', methods=['GET'])
@validate_token
def vfs_local_settings():
    """Exposes connection strings - CREDENTIAL LEAK."""
    log_access('VFS.Access', {'path': 'local.settings.json'}, request.remote_addr)

    return jsonify({
        'IsEncrypted': False,
        'Values': {
            'AzureWebJobsStorage': 'DefaultEndpointsProtocol=https;AccountName=proddata001;AccountKey=MOCK_LEAKED_KEY_BASE64==;',
            'FUNCTIONS_WORKER_RUNTIME': 'python',
            'DATABASE_CONNECTION': 'Server=tcp:prod-sql.database.windows.net;Database=customers;'
        }
    })


# Register base blueprint (provides /health, /healthz, /audit/logs, /admin/tokens, /admin/reset)
app.register_blueprint(create_base_blueprint(
    base,
    health_extras={'functionApp': FUNCTION_APP_NAME}
))


if __name__ == '__main__':
    print(f"Starting Azure Functions mock: {FUNCTION_APP_NAME}")
    app.run(host='0.0.0.0', port=7071)
