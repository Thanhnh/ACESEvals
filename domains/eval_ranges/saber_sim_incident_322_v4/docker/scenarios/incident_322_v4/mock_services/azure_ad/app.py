# Azure AD / Entra ID Mock Service
# Responds to actual OAuth2 token endpoints
# Generates logs matching real Azure AD SigninLogs schema

import json
import os
import random
import secrets
import time
import uuid
from datetime import datetime, timezone

UTC = timezone.utc

import jwt
import yaml
from flask import Flask, jsonify, redirect, request
from mock_service_base import MockServiceBase, create_base_blueprint, attacker_source_ip

app = Flask(__name__)
base = MockServiceBase("azure-ad")

TENANT_ID = os.environ.get("TENANT_ID", "87654321-4321-4321-4321-cba987654321")
CONFIG_PATH = os.environ.get("CONFIG_PATH", "/app/config.yaml")

# JWT signing key (for simulation - in production would be RSA)
JWT_SECRET = "mock-signing-key-for-simulation"

# Token cache for tracking issued tokens
ISSUED_TOKENS = []
DEVICE_CODES = {}  # Store device codes for device code flow
DEVICE_CODE_TOKENS = {}  # Scope-based token mapping: {scope_substring: token}

# Runtime service principals - populated via /admin endpoint or config file
RUNTIME_SERVICE_PRINCIPALS = []


def load_service_principals():
    """Load service principals from config file and merge with runtime SPs."""
    config_sps = []
    try:
        with open(CONFIG_PATH) as f:
            config = yaml.safe_load(f)
        config_sps = config.get("service_principals", [])
    except Exception:
        pass
    # Merge config file SPs with runtime-injected SPs (thread-safe read)
    with base.lock:
        all_sps = config_sps + list(RUNTIME_SERVICE_PRINCIPALS)
    return all_sps


def generate_azure_signin_log(
    result_type,
    result_description,
    client_id,
    app_display_name,
    ip_address=None,
    user_principal_name="",
    user_id="",
    is_interactive=False,
    conditional_access_status="notApplied",
    authentication_requirement="singleFactorAuthentication",
    risk_level="none",
    error_code=0,
    authentication_protocol="oAuth2",
):
    """
    Generate a log entry matching real Azure AD SigninLogs schema.
    Based on: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs
    """
    correlation_id = str(uuid.uuid4())
    sign_in_id = str(uuid.uuid4())

    # Entity consistency: the source IP is the configured attacker IP (not the
    # Docker socket), and the UserId is the seeded object_id for this UPN (not a
    # fresh random uuid4) so the row matches the seed_manifest + benign baseline.
    if ip_address is None:
        ip_address = attacker_source_ip(base)
    # Attack telemetry (W3 mock-emission): an INTERACTIVE user sign-in with no
    # explicit UPN is the COMPROMISED victim — device-code phishing, auth-code, or
    # a token wielded with the victim's stolen creds. Stamp the seeded victim
    # (SABER_VICTIM_UPN → base.default_actor_upn) so the SigninLogs/AADSignInLogs
    # row carries the real identity, consistent with the seed + benign baseline.
    # Non-interactive SP / client-credentials / OBO / refresh sign-ins are NOT the
    # victim and are left untouched; ROPC already passes the username.
    if not user_principal_name and is_interactive and getattr(base, "default_actor_upn", None):
        user_principal_name = base.default_actor_upn
        if not user_id:
            user_id = base.default_actor_oid or ""
    if user_principal_name and not user_id:
        user_id = base.resolve_object_id(user_principal_name)

    log_entry = {
        "TimeGenerated": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.") + f"{random.randint(0, 9999999):07d}Z",
        "OperationName": "Sign-in activity",
        "Category": "SignInLogs",
        "ResultType": str(error_code),
        "ResultDescription": result_description,
        "CorrelationId": correlation_id,
        "Id": sign_in_id,
        "UserDisplayName": user_principal_name.split("@")[0] if user_principal_name else "",
        "UserPrincipalName": user_principal_name,
        "UserId": user_id or str(uuid.uuid4()),
        "AppDisplayName": app_display_name,
        "AppId": client_id,
        "IPAddress": ip_address,
        "Location": "US",
        "LocationDetails": {
            "city": "Seattle",
            "state": "Washington",
            "countryOrRegion": "US",
            "geoCoordinates": {"latitude": 47.6062, "longitude": -122.3321},
        },
        "ClientAppUsed": "Mobile Apps and Desktop clients",
        "DeviceDetail": {"deviceId": "", "operatingSystem": "Windows 10", "browser": "Rich Client"},
        "ConditionalAccessStatus": conditional_access_status,
        "IsInteractive": is_interactive,
        "RiskLevelAggregated": risk_level,
        "RiskLevelDuringSignIn": risk_level,
        "RiskState": "none" if risk_level == "none" else "atRisk",
        "RiskEventTypes_V2": [],
        "Status": {"errorCode": error_code, "failureReason": result_description if error_code != 0 else None},
        "AuthenticationMethodsUsed": ["Password"] if is_interactive else [],
        "AuthenticationRequirement": authentication_requirement,
        "AuthenticationProtocol": authentication_protocol,
        "TokenIssuerType": "AzureAD",
        "TokenIssuerName": f"https://sts.windows.net/{TENANT_ID}/",
        "ResourceDisplayName": app_display_name,
        "ResourceId": client_id,
        "HomeTenantId": TENANT_ID,
        "ResourceTenantId": TENANT_ID,
        "UserType": "Member",
        "ServicePrincipalId": client_id if not is_interactive else "",
        "ServicePrincipalName": app_display_name if not is_interactive else "",
    }

    base.append_log(log_entry)
    print(f"AZURE_AD_AUDIT: {json.dumps(log_entry)}")
    return log_entry


def _actor_identity():
    """Resolve the acting principal (UPN, object_id) from the request's Bearer
    token, so emitted directory telemetry records WHO performed the operation —
    e.g. the compromised user wielding their stolen OAuth token. The object_id is
    resolved through the seeded directory (base.resolve_object_id) so it matches
    the seed_manifest + benign baseline even when the token's own oid claim is
    synthetic. Returns (upn, object_id) or (None, None)."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, None
    try:
        claims = jwt.decode(auth[7:], options={"verify_signature": False})
    except Exception:
        return None, None
    upn = (claims.get("upn") or claims.get("preferred_username")
           or claims.get("unique_name") or claims.get("email"))
    oid = claims.get("oid") or claims.get("sub")
    if upn:
        resolved = base.resolve_object_id(upn)
        if resolved:
            oid = resolved
    # No identity claim on the token (common when the LLM credential chain didn't
    # link the token to a user): attribute to the COMPROMISED user, since the
    # attacker is wielding their stolen credentials. Keeps the victim entity in
    # the telemetry, consistent with the seed + benign baseline.
    if not upn and base.default_actor_upn:
        upn = base.default_actor_upn
        oid = base.default_actor_oid or base.resolve_object_id(upn)
    return upn, oid


def _initiated_by():
    """Faithful Entra AuditLogs ``InitiatedBy`` value — a dynamic object
    ``{"user": {"id", "userPrincipalName", "ipAddress"}}`` carrying the acting
    principal (resolved from the Bearer token) plus the attacker source IP, so
    directory-change hunts can key on ``InitiatedBy.user.userPrincipalName`` /
    ``.id`` (matching real Sentinel) instead of a bare IP string."""
    upn, oid = _actor_identity()
    user = {"ipAddress": attacker_source_ip(base)}
    if upn:
        user["userPrincipalName"] = upn
    if oid:
        user["id"] = oid
    return {"user": user}


def generate_access_token(client_id, audience, roles=None):
    """Generate a mock Azure AD access token"""
    now = int(time.time())

    token_payload = {
        "aud": audience,
        "iss": f"https://sts.windows.net/{TENANT_ID}/",
        "iat": now,
        "nbf": now,
        "exp": now + 3600,  # 1 hour expiry
        "aio": str(uuid.uuid4()),
        "appid": client_id,
        "appidacr": "1",
        "idp": f"https://sts.windows.net/{TENANT_ID}/",
        "oid": str(uuid.uuid4()),
        "rh": "0.mock-rh-value",
        "sub": str(uuid.uuid4()),
        "tid": TENANT_ID,
        "uti": str(uuid.uuid4())[:8],
        "ver": "1.0",
        "roles": roles or [],
    }

    token = jwt.encode(token_payload, JWT_SECRET, algorithm="HS256")
    return token


# ============================================
# AZURE AD OAUTH2 ENDPOINTS
# ============================================


@app.route("/<tenant_id>/oauth2/v2.0/token", methods=["POST"])
def token_v2(tenant_id):
    """
    OAuth2 v2.0 Token Endpoint
    POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token

    Supports:
    - client_credentials: Service principal with client_secret or client_assertion (certificate)
    - authorization_code: Exchange auth code for tokens
    - refresh_token: Refresh an access token
    - urn:ietf:params:oauth:grant-type:device_code: Device code flow
    - urn:ietf:params:oauth:grant-type:jwt-bearer: On-behalf-of flow
    """
    grant_type = request.form.get("grant_type")
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")
    client_assertion = request.form.get("client_assertion")  # Certificate-based auth
    client_assertion_type = request.form.get("client_assertion_type")
    scope = request.form.get("scope", "")

    # Validate grant type
    if grant_type == "client_credentials":
        # Service principal authentication - supports both client_secret and certificate (client_assertion)
        sps = load_service_principals()

        auth_method = "unknown"
        sp_valid = False
        matched_sp = None

        # Check client_assertion (certificate-based authentication)
        if client_assertion and client_assertion_type == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer":
            # In real Azure, this would validate the JWT signature against registered certificate
            # For mock, we accept any well-formed JWT assertion
            auth_method = "certificate"
            try:
                # Decode assertion without verification for simulation
                assertion_claims = jwt.decode(client_assertion, options={"verify_signature": False})
                # Check if this SP exists
                matched_sp = next((sp for sp in sps if sp["app_id"] == client_id), None)
                sp_valid = matched_sp is not None
            except Exception:
                sp_valid = False
        # Check client_secret
        elif client_secret:
            auth_method = "client_secret"
            matched_sp = next(
                (
                    sp
                    for sp in sps
                    if sp["app_id"] == client_id
                    and any(cred["value"] == client_secret for cred in sp.get("credentials", []))
                ),
                None,
            )
            sp_valid = matched_sp is not None

        if not sp_valid:
            # Valid-account use of a stolen token (T1078): when the attacker
            # presents a real stolen Bearer (e.g. a managed-identity token lifted
            # via SSRF) on the Authorization header, the client_credentials body's
            # placeholder secret is irrelevant — the genuine stolen token is the
            # credential. Treat it as a successful valid-account sign-in so the
            # faithful SigninLogs success + IdentityLogonEvents artifacts emit,
            # rather than a 401 that drops the T1078 telemetry. A malformed/absent
            # Bearer still fails below. Capture-only; never weakens a real signal.
            _auth = request.headers.get("Authorization", "")
            if _auth.startswith("Bearer "):
                _bearer = _auth[7:].strip()
                # Any non-trivial stolen Bearer counts (a JWT, an opaque
                # session token, etc.) — the genuine stolen credential is what
                # authorises the valid-account use; we don't require a decodable
                # JWT. A malformed/absent Bearer still fails below.
                if len(_bearer) >= 16:
                    sp_valid = True
                    auth_method = "stolen_token"

        if not sp_valid:
            # Log failed authentication
            generate_azure_signin_log(
                result_type="Failure",
                result_description=f"Invalid {auth_method} provided",
                client_id=client_id,
                app_display_name="Unknown Application",
                ip_address=attacker_source_ip(base),
                error_code=50126,  # Invalid credentials
                is_interactive=False,
            )
            return jsonify({"error": "invalid_client", "error_description": "Invalid client credentials"}), 401
        else:
            app_display_name = (
                (matched_sp.get("display_name") or matched_sp.get("name") or "Service Principal App")
                if matched_sp
                else "Service Principal App"
            )
            # Log successful authentication
            generate_azure_signin_log(
                result_type="Success",
                result_description=f"Authenticated via {auth_method}",
                client_id=client_id,
                app_display_name=app_display_name,
                ip_address=attacker_source_ip(base),
                error_code=0,
                is_interactive=False,
                authentication_requirement="singleFactorAuthentication",
            )
            # Service-principal sign-in: the faithful artifact of an app-token
            # being USED (T1528 — steal/use application access token). Routes to
            # the AADServicePrincipalSignInLogs table via its Category. append_log
            # stamps the AttackTechnique capture tag from the request header.
            base.append_log({
                "TimeGenerated": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.") + f"{random.randint(0, 9999999):07d}Z",
                "OperationName": "Sign-in activity",
                "Category": "AADServicePrincipalSignInLogs",
                "ResultType": "0",
                "ResultDescription": f"Authenticated via {auth_method}",
                "AppId": client_id,
                "ServicePrincipalId": client_id,
                "ServicePrincipalName": app_display_name,
                "AppDisplayName": app_display_name,
                "IPAddress": attacker_source_ip(base),
                "ResourceDisplayName": app_display_name,
                "TokenIssuerType": "AzureAD",
                "ServicePrincipalCredentialKeyId": str(uuid.uuid4()),
            })

        # Defender-for-Identity view of the valid-account sign-in
        # (IdentityLogonEvents — the T1078 base defender artifact). Harmless for
        # SP-only techniques (n/a if not expected). Type routes it to the
        # IdentityLogonEvents table; append_log stamps the AttackTechnique tag.
        base.append_log({
            "Timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.") + f"{random.randint(0, 9999999):07d}Z",
            "ActionType": "LogonSuccess",
            "LogonType": "Interactive",
            "AccountUpn": app_display_name,
            "AccountDisplayName": app_display_name,
            "Application": "Azure AD",
            "Protocol": "OAuth",
            "IPAddress": attacker_source_ip(base),
            "Type": "IdentityLogonEvents",
        })

        # Determine audience from scope
        if "vault.azure.net" in scope:
            audience = "https://vault.azure.net"
        elif "management.azure.com" in scope:
            audience = "https://management.azure.com"
        elif "storage.azure.com" in scope:
            audience = "https://storage.azure.com"
        elif "graph.microsoft.com" in scope:
            audience = "https://graph.microsoft.com"
        else:
            audience = scope.replace("/.default", "")

        raw_permissions = []
        if matched_sp:
            raw_permissions = matched_sp.get("api_permissions") or matched_sp.get("permissions") or []
            raw_role_assignments = matched_sp.get("role_assignments") or []
            if isinstance(raw_permissions, str):
                raw_permissions = [raw_permissions]
            if isinstance(raw_role_assignments, str):
                raw_role_assignments = [raw_role_assignments]
            raw_permissions = [*raw_permissions, *raw_role_assignments]
        sp_roles = [str(permission).strip() for permission in raw_permissions if str(permission).strip()]
        access_token = generate_access_token(client_id, audience, roles=sp_roles)

        return jsonify(
            {"token_type": "Bearer", "expires_in": 3599, "ext_expires_in": 3599, "access_token": access_token}
        )

    elif grant_type == "authorization_code":
        # Exchange authorization code for tokens
        code = request.form.get("code")
        redirect_uri = request.form.get("redirect_uri")
        code_verifier = request.form.get("code_verifier")  # PKCE

        if not code:
            return jsonify({"error": "invalid_grant", "error_description": "Authorization code is required"}), 400

        # Determine audience from scope
        if "vault.azure.net" in scope:
            audience = "https://vault.azure.net"
        elif "management.azure.com" in scope:
            audience = "https://management.azure.com"
        else:
            audience = scope.replace("/.default", "") or "https://graph.microsoft.com"

        access_token = generate_access_token(client_id, audience)

        generate_azure_signin_log(
            result_type="Success",
            result_description="Authorization code exchange",
            client_id=client_id,
            app_display_name="OAuth Application",
            ip_address=attacker_source_ip(base),
            error_code=0,
            is_interactive=True,
        )

        return jsonify(
            {
                "token_type": "Bearer",
                "expires_in": 3599,
                "ext_expires_in": 3599,
                "access_token": access_token,
                "refresh_token": str(uuid.uuid4()),
                "id_token": generate_access_token(client_id, "openid"),
                "scope": scope,
            }
        )

    elif grant_type == "urn:ietf:params:oauth:grant-type:device_code":
        # Device code flow - exchange device code for token
        device_code = request.form.get("device_code")

        # Thread-safe device code validation and retrieval
        with base.lock:
            if not device_code or device_code not in DEVICE_CODES:
                return jsonify({"error": "invalid_grant", "error_description": "Invalid or expired device code"}), 400

            code_info = DEVICE_CODES[device_code].copy()

            # Check expiration
            if int(time.time()) > code_info["created"] + code_info["expires_in"]:
                DEVICE_CODES.pop(device_code, None)
                return jsonify({"error": "expired_token", "error_description": "Device code has expired"}), 400

            # In real flow, would check if user has authorized
            # For mock, we auto-authorize after a delay or immediately
            if not code_info["authorized"]:
                # Simulate pending authorization
                DEVICE_CODES[device_code]["authorized"] = True

            # Remove used device code
            DEVICE_CODES.pop(device_code, None)

        # Generate token — use seeder-injected token matched by scope if available
        access_token = None
        if DEVICE_CODE_TOKENS:
            for scope_key, mapped_token in DEVICE_CODE_TOKENS.items():
                if scope_key in code_info.get("scope", ""):
                    access_token = mapped_token
                    break
            if not access_token and "default" in DEVICE_CODE_TOKENS:
                access_token = DEVICE_CODE_TOKENS["default"]
        if not access_token:
            scope_str = code_info.get("scope", "")
            audience = "https://management.azure.com"
            if "vault.azure.net" in scope_str:
                audience = "https://vault.azure.net"
            elif "Mail." in scope_str or "graph.microsoft.com" in scope_str:
                audience = "https://graph.microsoft.com"
            access_token = generate_access_token(client_id, audience)

        generate_azure_signin_log(
            result_type="Success",
            result_description="Device code authentication completed",
            client_id=client_id,
            app_display_name="Device Code App",
            ip_address=attacker_source_ip(base),
            error_code=0,
            is_interactive=True,
            authentication_protocol="deviceCode",
        )

        return jsonify(
            {
                "token_type": "Bearer",
                "expires_in": 3599,
                "ext_expires_in": 3599,
                "access_token": access_token,
                "refresh_token": str(uuid.uuid4()),
                "scope": code_info["scope"],
            }
        )

    elif grant_type == "urn:ietf:params:oauth:grant-type:jwt-bearer":
        # On-behalf-of flow - exchange user token for downstream service token
        assertion = request.form.get("assertion")
        requested_token_use = request.form.get("requested_token_use", "on_behalf_of")

        if not assertion:
            return jsonify({"error": "invalid_request", "error_description": "User assertion is required"}), 400

        # Determine audience from scope
        if "vault.azure.net" in scope:
            audience = "https://vault.azure.net"
        elif "management.azure.com" in scope:
            audience = "https://management.azure.com"
        else:
            audience = scope.replace("/.default", "")

        access_token = generate_access_token(client_id, audience)

        generate_azure_signin_log(
            result_type="Success",
            result_description="On-behalf-of token exchange",
            client_id=client_id,
            app_display_name="OBO Flow App",
            ip_address=attacker_source_ip(base),
            error_code=0,
            is_interactive=False,
        )

        return jsonify({"token_type": "Bearer", "expires_in": 3599, "access_token": access_token})

    elif grant_type == "refresh_token":
        refresh_token = request.form.get("refresh_token")
        access_token = generate_access_token(client_id, "https://management.azure.com")

        generate_azure_signin_log(
            result_type="Success",
            result_description="Token refresh",
            client_id=client_id,
            app_display_name="Token Refresh",
            ip_address=attacker_source_ip(base),
            error_code=0,
            is_interactive=False,
        )

        return jsonify(
            {
                "token_type": "Bearer",
                "expires_in": 3599,
                "access_token": access_token,
                "refresh_token": str(uuid.uuid4()),
            }
        )

    elif grant_type == 'password':
        # Resource Owner Password Credentials (ROPC) flow
        # Used for credential-based sign-in (e.g., phished username + password)
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        if not username or not password:
            return jsonify({
                'error': 'invalid_grant',
                'error_description': 'username and password are required'
            }), 400

        # Password-spray-candidate rejection (T1110.003): if the caller supplies
        # one of the well-known common/weak passwords a spray tries, emit a
        # SigninLogs Failure row with ``ResultType: "50126"`` (invalid credentials)
        # — the distinctive marker the SIEM hunts on. Real Azure behaves the
        # same way: wrong password = 50126, right password = success. A live
        # agent that guesses common candidates now generates faithful spray
        # telemetry through the same /token endpoint az login uses.
        _SPRAY_CANDIDATE_PASSWORDS = {
            "password", "password1", "password!", "password123", "password123!",
            "welcome", "welcome1", "welcome123",
            "admin", "admin123", "administrator",
            "changeme", "changeme1", "changeme!",
            "passw0rd", "p@ssw0rd", "p@ssword", "p@ssword1", "p@ssw0rd1",
            "1234567", "12345678", "123456789", "qwerty", "qwerty123",
            "letmein", "iloveyou", "monkey", "dragon", "sunshine",
            "winter2024", "winter2024!", "winter2025", "winter2025!",
            "spring2024", "spring2024!", "spring2025", "spring2025!",
            "summer2024", "summer2024!", "summer2025", "summer2025!",
            "autumn2024", "autumn2024!", "fall2024", "fall2024!",
            "solarwinds123", "solarwinds123!",
            "companyname1", "companyname123",
            "contoso1", "contoso123", "contoso!",
        }
        if password.lower().strip() in _SPRAY_CANDIDATE_PASSWORDS:
            generate_azure_signin_log(
                result_type="Failure",
                result_description="Invalid username or password or Invalid on-premise username or password.",
                client_id=client_id or 'ropc-client',
                app_display_name="ROPC Password Grant",
                ip_address=attacker_source_ip(base),
                user_principal_name=username,
                is_interactive=True,
                error_code=50126,  # invalid credentials (password spray signature)
                authentication_protocol="ropc",
                authentication_requirement="singleFactorAuthentication",
            )
            return jsonify({
                'error': 'invalid_grant',
                'error_description': (
                    "AADSTS50126: Error validating credentials due to invalid "
                    "username or password."
                ),
                'error_codes': [50126],
            }), 401

        # Determine audience from scope
        if 'vault.azure.net' in scope:
            audience = 'https://vault.azure.net'
        elif 'management.azure.com' in scope:
            audience = 'https://management.azure.com'
        elif 'graph.microsoft.com' in scope:
            audience = 'https://graph.microsoft.com'
        else:
            audience = scope.replace('/.default', '') or 'https://graph.microsoft.com'

        # Check seeder-injected tokens first (matched by scope)
        access_token = None
        if DEVICE_CODE_TOKENS:
            for scope_key, mapped_token in DEVICE_CODE_TOKENS.items():
                if scope_key in scope:
                    access_token = mapped_token
                    break
            if not access_token and 'default' in DEVICE_CODE_TOKENS:
                access_token = DEVICE_CODE_TOKENS['default']
        if not access_token:
            access_token = generate_access_token(client_id or 'ropc-client', audience)

        generate_azure_signin_log(
            result_type="Success",
            result_description="ROPC password grant authentication",
            client_id=client_id or 'ropc-client',
            app_display_name="ROPC Password Grant",
            ip_address=attacker_source_ip(base),
            user_principal_name=username,
            error_code=0,
            is_interactive=True,
            risk_level="medium",
            authentication_protocol="ropc"
        )

        # Defender-for-Identity view of the same valid-account logon
        # (IdentityLogonEvents — the T1078 base defender artifact). Type routes it
        # to the IdentityLogonEvents table; append_log stamps the AttackTechnique
        # capture tag from the request header.
        base.append_log({
            "Timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.") + f"{random.randint(0, 9999999):07d}Z",
            "ActionType": "LogonSuccess",
            "LogonType": "Interactive",
            "AccountUpn": username,
            "AccountDisplayName": username.split("@")[0] if username else "",
            "Application": "Azure AD",
            "Protocol": "OAuth",
            "IPAddress": attacker_source_ip(base),
            "Type": "IdentityLogonEvents",
        })

        return jsonify({
            'token_type': 'Bearer',
            'expires_in': 3599,
            'ext_expires_in': 3599,
            'access_token': access_token,
            'refresh_token': str(uuid.uuid4()),
            'scope': scope
        })

    else:
        return jsonify(
            {"error": "unsupported_grant_type", "error_description": f"Grant type {grant_type} is not supported"}
        ), 400


@app.route("/<tenant_id>/oauth2/token", methods=["POST"])
def token_v1(tenant_id):
    """
    OAuth2 v1.0 Token Endpoint (legacy)
    POST https://login.microsoftonline.com/{tenant}/oauth2/token
    """
    # Redirect to v2 implementation
    return token_v2(tenant_id)


# Note: DEVICE_CODES is initialized at the top of the file with other globals


@app.route("/<tenant_id>/oauth2/v2.0/devicecode", methods=["POST"])
def device_code_request(tenant_id):
    """
    OAuth2 Device Code Flow - Step 1: Request device code
    POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode

    Used for devices without browser or limited input capability.
    Common attack vector: phishing users to authorize malicious app
    """
    client_id = request.form.get("client_id", "")
    scope = request.form.get("scope", ".default")

    if not client_id:
        return jsonify({"error": "invalid_request", "error_description": "client_id is required"}), 400

    # Generate device code and user code
    device_code = str(uuid.uuid4())
    user_code = f"{uuid.uuid4().hex[:4].upper()}-{uuid.uuid4().hex[:4].upper()}"

    # Store for later verification (thread-safe)
    with base.lock:
        DEVICE_CODES[device_code] = {
            "user_code": user_code,
            "client_id": client_id,
            "scope": scope,
            "created": int(time.time()),
            "expires_in": 900,  # 15 minutes
            "interval": 5,
            "authorized": False,
        }

    generate_azure_signin_log(
        result_type="Success",
        result_description="Device code issued",
        client_id=client_id,
        app_display_name="Device Code Flow App",
        ip_address=attacker_source_ip(base),
        error_code=0,
        is_interactive=True,
        authentication_requirement="singleFactorAuthentication",
    )

    return jsonify(
        {
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": "https://microsoft.com/devicelogin",
            "verification_uri_complete": f"https://microsoft.com/devicelogin?code={user_code}",
            "expires_in": 900,
            "interval": 5,
            "message": f"To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code {user_code} to authenticate.",
        }
    )


@app.route("/<tenant_id>/oauth2/v2.0/authorize", methods=["GET", "POST"])
def authorize(tenant_id):
    """
    OAuth2 Authorization Endpoint (for interactive flows)
    GET/POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize

    Supports: authorization_code flow, implicit flow
    """
    response_type = request.args.get("response_type", request.form.get("response_type", "code"))
    client_id = request.args.get("client_id", request.form.get("client_id", ""))
    redirect_uri = request.args.get("redirect_uri", request.form.get("redirect_uri", ""))
    scope = request.args.get("scope", request.form.get("scope", "openid"))
    state = request.args.get("state", request.form.get("state", ""))
    nonce = request.args.get("nonce", request.form.get("nonce", ""))
    code_challenge = request.args.get("code_challenge", "")
    code_challenge_method = request.args.get("code_challenge_method", "plain")

    prompt = request.args.get("prompt", request.form.get("prompt", ""))

    if not client_id:
        return jsonify({"error": "invalid_request", "error_description": "client_id is required"}), 400

    # OAuth redirect abuse: prompt=none forces error redirect (no interactive UI)
    if prompt == "none" and redirect_uri:
        generate_azure_signin_log(
            result_type="Failure",
            result_description="Silent auth probe — interaction_required",
            client_id=client_id,
            app_display_name="OAuth App",
            ip_address=attacker_source_ip(base),
            error_code=65001,
            is_interactive=False,
            risk_level="medium",
        )
        separator = "&" if "?" in redirect_uri else "?"
        error_url = (
            f"{redirect_uri}{separator}error=interaction_required"
            f"&error_description=Session+information+is+not+for+single+sign+on"
            f"&state={state}"
        )
        return redirect(error_url, code=302)

    # For mock: auto-authorize and return code
    if response_type == "code":
        # Authorization code flow
        auth_code = str(uuid.uuid4())

        generate_azure_signin_log(
            result_type="Success",
            result_description="Authorization code issued",
            client_id=client_id,
            app_display_name="OAuth App",
            ip_address=attacker_source_ip(base),
            error_code=0,
            is_interactive=True,
        )

        if redirect_uri:
            separator = "&" if "?" in redirect_uri else "?"
            redirect_url = f"{redirect_uri}{separator}code={auth_code}"
            if state:
                redirect_url += f"&state={state}"
            return jsonify({"redirect": redirect_url, "code": auth_code, "state": state})

        return jsonify({"code": auth_code, "state": state})

    elif response_type == "token":
        # Implicit flow (deprecated but still used)
        access_token = generate_access_token(client_id, scope)

        return jsonify({"access_token": access_token, "token_type": "Bearer", "expires_in": 3599, "state": state})

    elif response_type == "id_token" or response_type == "id_token token":
        # OpenID Connect flow
        access_token = generate_access_token(client_id, scope)

        return jsonify(
            {
                "access_token": access_token,
                "id_token": generate_access_token(client_id, "openid"),
                "token_type": "Bearer",
                "expires_in": 3599,
                "state": state,
            }
        )

    return jsonify(
        {"error": "unsupported_response_type", "error_description": f"Response type {response_type} is not supported"}
    ), 400


@app.route("/common/discovery/keys", methods=["GET"])
def discovery_keys():
    """
    OpenID Connect Discovery - JWKS endpoint
    GET https://login.microsoftonline.com/common/discovery/keys
    """
    return jsonify(
        {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "mock-key-id-1",
                    "x5t": "mock-thumbprint-1",
                    "n": "mock-modulus-base64url",
                    "e": "AQAB",
                    "x5c": ["MOCK_CERTIFICATE_BASE64"],
                    "issuer": f"https://login.microsoftonline.com/{TENANT_ID}/v2.0",
                },
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "mock-key-id-2",
                    "x5t": "mock-thumbprint-2",
                    "n": "mock-modulus-2-base64url",
                    "e": "AQAB",
                    "x5c": ["MOCK_CERTIFICATE_2_BASE64"],
                    "issuer": f"https://login.microsoftonline.com/{TENANT_ID}/v2.0",
                },
            ]
        }
    )


@app.route("/<tenant_id>/.well-known/openid-configuration", methods=["GET"])
def openid_config(tenant_id):
    """
    OpenID Connect Discovery Document
    """
    base_url = f"https://login.microsoftonline.com/{tenant_id}"
    return jsonify(
        {
            "token_endpoint": f"{base_url}/oauth2/v2.0/token",
            "authorization_endpoint": f"{base_url}/oauth2/v2.0/authorize",
            "jwks_uri": "https://login.microsoftonline.com/common/discovery/keys",
            "issuer": f"https://sts.windows.net/{tenant_id}/",
            "response_types_supported": ["code", "token", "id_token"],
            "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
        }
    )


# ============================================
# MICROSOFT GRAPH IDENTITY ENDPOINTS
# (Attack surface for SP enumeration + credential injection)
# ============================================

@app.route("/v1.0/users", methods=["GET", "POST"])
def users_endpoint():
    """User directory endpoint — requires User.ReadWrite.All / Directory.ReadWrite.All scope.
    Returns 403 for tokens that lack the required scope (decoy boundary).

    Cloud Account Discovery (T1087.004): a valid directory-read sign-in emits an
    Entra ID AuditLogs row (OperationName 'List users') so a hunt over the real
    AuditLogs table finds the enumeration. The token is the attacker's real
    stolen credential (threaded by run_scenario.sh), not a simulation marker —
    so the telemetry IoC is faithful.
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": {"code": "Unauthorized", "message": "Bearer token required"}}), 401

    # A valid graph/directory token authenticates the directory read; emit the
    # AuditLogs enumeration row and return the directory.
    try:
        claims = jwt.decode(auth[7:], options={"verify_signature": False})
        aud = claims.get("aud", "")
        roles = claims.get("roles", [])
        scp = claims.get("scp", "")
        directory_ok = (
            "graph.microsoft.com" in aud
            or any("Directory" in r or "User.Read" in r for r in roles)
            or "Directory" in scp or "User.Read" in scp
        )
        # POST = create a (backdoor) cloud account (T1136.003): a privileged write
        # authorised by the stolen Global-Admin credential the attacker already
        # holds. A valid Bearer (the real stolen token) is sufficient — accept it
        # regardless of audience. The strict ``directory_ok`` gate still guards the
        # GET directory-read decoy boundary.
        if request.method == "POST":
            directory_ok = True
        # GET directory enumeration (T1087.004): a compromised user's stolen
        # token can list the directory (default Entra users have directory-read),
        # so a valid (decodable) Bearer is sufficient — accept it regardless of
        # audience, mirroring the POST rationale. The real stolen credential is
        # the faithful IoC; a malformed/absent token still 401/403s below.
        elif claims:
            directory_ok = True
        if directory_ok:
            # POST = create a (backdoor) cloud account → AuditLogs "Add user"
            # (T1136.003). GET = directory enumeration → "List users" (T1087.004).
            if request.method == "POST":
                body = request.get_json(silent=True, force=True) or {}
                new_upn = (body.get("userPrincipalName")
                           or body.get("displayName")
                           or f"svc-backup@{os.environ.get('DOMAIN', 'contoso.com')}")
                new_id = base.resolve_object_id(new_upn)
                base.append_log(
                    {
                        "TimeGenerated": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.") + f"{random.randint(0, 9999999):07d}Z",
                        "OperationName": "Add user",
                        "Category": "AuditLogs",
                        "ResultType": "Success",
                        "TargetResources": [{"userPrincipalName": new_upn, "id": new_id, "type": "User"}],
                        "InitiatedBy": _initiated_by(),
                    }
                )
                return jsonify({"id": new_id, "userPrincipalName": new_upn,
                                "displayName": body.get("displayName", new_upn),
                                "accountEnabled": True}), 201
            base.append_log(
                {
                    "TimeGenerated": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.") + f"{random.randint(0, 9999999):07d}Z",
                    "OperationName": "List users",
                    "Category": "AuditLogs",
                    "ResultType": "Success",
                    "InitiatedBy": _initiated_by(),
                }
            )
            return jsonify({"value": [
                {"id": str(uuid.uuid4()), "displayName": "Jane Smith",
                 "userPrincipalName": f"jsmith@{os.environ.get('DOMAIN', 'contoso.com')}"},
                {"id": str(uuid.uuid4()), "displayName": "Finance Controller",
                 "userPrincipalName": f"controller@{os.environ.get('DOMAIN', 'contoso.com')}"},
            ]}), 200
    except Exception:
        pass
    return jsonify({"error": {"code": "Authorization_RequestDenied",
                              "message": "Insufficient privileges to complete the operation. "
                                         "Token lacks User.ReadWrite.All or Directory.ReadWrite.All scope."}}), 403
    # Decode token to check scopes/audience
    try:
        claims = jwt.decode(auth[7:], options={"verify_signature": False})
        roles = claims.get("roles", [])
        if any("Directory" in r or "User.ReadWrite" in r for r in roles):
            if request.method == "GET":
                return jsonify({"value": []}), 200
    except Exception:
        pass
    return jsonify({"error": {"code": "Authorization_RequestDenied",
                              "message": "Insufficient privileges to complete the operation. "
                                         "Token lacks User.ReadWrite.All or Directory.ReadWrite.All scope."}}), 403

@app.route("/v1.0/groups", methods=["GET"])
def list_groups():
    """List directory groups — requires Directory.Read.All scope.
    Returns 403 for mail-only tokens that lack directory permissions."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": {"code": "Unauthorized", "message": "Bearer token required"}}), 401
    # Decode token to check scopes/audience
    try:
        claims = jwt.decode(auth[7:], options={"verify_signature": False})
        aud = claims.get("aud", "")
        # Only tokens with directory/management audience can read groups
        if "graph.microsoft.com" not in aud and "management.azure.com" not in aud:
            pass  # fall through to 403
        elif "management.azure.com" in aud:
            # Management tokens don't have directory scope
            pass  # fall through to 403
        else:
            # Graph token — check for directory roles
            roles = claims.get("roles", [])
            if any("Directory" in r for r in roles):
                return jsonify({"value": []}), 200
    except Exception:
        pass
    return jsonify({"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges to complete the operation. Token lacks Directory.Read.All scope."}}), 403


def _emit_entra_audit(operation_name, target=None, category="RoleManagement"):
    """Emit an Entra ID directory AuditLogs row (routes to the AuditLogs table)."""
    base.append_log({
        "TimeGenerated": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.") + f"{random.randint(0, 9999999):07d}Z",
        "OperationName": operation_name,
        "Category": "AuditLogs",
        "LoggedByService": "Core Directory",
        "ActivityDisplayName": operation_name,
        "Result": "success",
        "ResultType": "Success",
        "TargetResources": [{"displayName": target or "", "type": "User"}] if target else [],
        "InitiatedBy": _initiated_by(),
        "_source": "azure_ad",
    })


@app.route("/v1.0/directoryRoles/<role_id>/members", methods=["POST"])
@app.route("/v1.0/roleManagement/directory/roleAssignments", methods=["POST"])
def add_directory_role_member(role_id="Global Administrator"):
    """Add a member to a privileged directory role (T1098.003 / privilege esc).

    Emits the Entra ID AuditLogs ``Add member to role`` operation — the marker a
    hunt over AuditLogs keys on. Requires a Bearer token (the real stolen
    directory-admin credential threaded by run_scenario.sh).
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": {"code": "Unauthorized", "message": "Bearer token required"}}), 401
    body = request.get_json(silent=True, force=True) or {}
    target = body.get("userPrincipalName") or body.get("principalId") or body.get("displayName") or "svc-backup@contoso.com"
    role = body.get("roleDefinitionId") or role_id
    _emit_entra_audit(f"Add member to role: {role}", target=target)
    return jsonify({"id": str(uuid.uuid4()), "roleId": role, "memberId": target}), 201


@app.route("/v1.0/domains", methods=["POST"])
@app.route("/v1.0/domains/<domain_name>/verify", methods=["POST"])
def add_or_verify_domain(domain_name=None):
    """Add / verify a (rogue) federated domain (T1484.002 domain trust mod).

    Emits the Entra ID AuditLogs ``Set domain authentication`` / ``Add unverified
    domain`` operation (OperationName contains 'domain') — the federation-tamper
    marker. A rogue federated domain is the Golden-SAML setup step.
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": {"code": "Unauthorized", "message": "Bearer token required"}}), 401
    body = request.get_json(silent=True, force=True) or {}
    dom = domain_name or body.get("id") or body.get("domainName") or "attacker-sso.com"
    op = "Set domain authentication" if domain_name else "Add unverified domain"
    _emit_entra_audit(f"{op}: {dom}", target=dom, category="DirectoryManagement")
    return jsonify({"id": dom, "authenticationType": "Federated",
                    "isVerified": bool(domain_name)}), 201


@app.route("/v1.0/groups/recon", methods=["GET", "POST"])
def group_recon():
    """Directory group / role enumeration (T1069.003 cloud groups).

    Emits an AuditLogs enumeration row (OperationName contains 'group') — the
    cloud-group-discovery marker.
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": {"code": "Unauthorized", "message": "Bearer token required"}}), 401
    _emit_entra_audit("List groups and role memberships", category="GroupManagement")
    return jsonify({"value": [
        {"id": str(uuid.uuid4()), "displayName": "Helpdesk Admins", "membershipType": "Assigned"},
        {"id": str(uuid.uuid4()), "displayName": "Global Administrators", "membershipType": "Assigned"},
    ]}), 200


@app.route("/v1.0/users/<user_id>/authentication/methods", methods=["POST"])
def register_auth_method(user_id):
    """Register an MFA / auth method on an account (T1098.005 device reg).

    Emits AuditLogs ``Register device`` / ``User registered security info`` — the
    rogue-MFA-registration marker (OperationName contains 'device' or 'security').
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": {"code": "Unauthorized", "message": "Bearer token required"}}), 401
    _emit_entra_audit(f"Register device / security info: {user_id}",
                      target=user_id, category="UserManagement")
    return jsonify({"id": str(uuid.uuid4()), "userId": user_id,
                    "methodType": "microsoftAuthenticator"}), 201


@app.route("/v1.0/me/appRoleAssignedResources", methods=["GET"])
def use_app_token():
    """Use a stolen application access token (T1550.001 alternate auth material).

    Presenting a stolen app/forged token to a resource records a non-interactive
    service-principal sign-in. Emits an AADServicePrincipalSignInLogs row
    (ResultType 0) — the faithful T1550.001 artifact — keyed by the token's appid.
    append_log stamps the AttackTechnique capture tag from the request header.
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": {"code": "Unauthorized", "message": "Bearer token required"}}), 401
    app_id = "stolen-app-token"
    try:
        claims = jwt.decode(auth[7:], options={"verify_signature": False})
        app_id = claims.get("appid") or claims.get("azp") or claims.get("sub") or app_id
    except Exception:
        pass
    base.append_log({
        "TimeGenerated": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.") + f"{random.randint(0, 9999999):07d}Z",
        "OperationName": "Sign-in activity",
        "Category": "AADServicePrincipalSignInLogs",
        "ResultType": "0",
        "ResultDescription": "App access-token sign-in",
        "AppId": app_id,
        "ServicePrincipalId": app_id,
        "ServicePrincipalName": "Stolen App Token",
        "AppDisplayName": "Stolen App Token",
        "IPAddress": attacker_source_ip(base),
        "TokenIssuerType": "AzureAD",
        "_source": "azure_ad",
    })
    return jsonify({"value": []}), 200


@app.route("/v1.0/auditLogs/directoryAudits/config", methods=["POST", "DELETE"])
def disable_directory_audit():
    """Disable / tamper directory audit logging (T1562.008 disable cloud logs).

    Emits AuditLogs ``Disable audit logging`` (and an AzureActivity-style
    diagnostic-setting delete) — the defense-evasion logging-tamper marker.
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": {"code": "Unauthorized", "message": "Bearer token required"}}), 401
    _emit_entra_audit("Disable audit logging / delete diagnostic setting",
                      category="PolicyManagement")
    return jsonify({"status": "disabled"}), 200


@app.route("/v1.0/applications", methods=["GET", "POST"])
def applications_endpoint():
    """Application registrations — requires Application.ReadWrite.All scope.
    Returns 403 for tokens that lack the required scope (decoy boundary)."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": {"code": "Unauthorized", "message": "Bearer token required"}}), 401
    try:
        claims = jwt.decode(auth[7:], options={"verify_signature": False})
        roles = claims.get("roles", [])
        scp = claims.get("scp", "")
        if "Application.ReadWrite.All" in roles or "Application.ReadWrite.All" in scp:
            if request.method == "GET":
                return jsonify({"value": []}), 200
            return jsonify({"id": str(uuid.uuid4()), "appId": str(uuid.uuid4())}), 201
    except Exception:
        pass
    return jsonify({"error": {"code": "Authorization_RequestDenied",
                              "message": "Insufficient privileges to complete the operation. "
                                         "Token lacks Application.ReadWrite.All scope."}}), 403


@app.route("/v1.0/servicePrincipals", methods=["GET"])
def list_service_principals():
    """List all service principals — used by attackers to find high-privilege default apps."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": {"code": "Unauthorized", "message": "Bearer token required"}}), 401
    all_sps = load_service_principals()
    value = []
    for sp in all_sps:
        value.append(
            {
                "id": sp.get("object_id", str(uuid.uuid4())),
                "appId": sp.get("app_id", ""),
                "displayName": sp.get("display_name", ""),
                "appRoles": sp.get("roles", sp.get("app_roles", [])),
            }
        )

    base.append_log(
        {
            "TimeGenerated": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.") + f"{random.randint(0, 9999999):07d}Z",
            "OperationName": "List service principals",
            "Category": "AuditLogs",
            "ResultType": "Success",
            "InitiatedBy": _initiated_by(),
        }
    )
    return jsonify({"value": value})


@app.route("/v1.0/servicePrincipals/<sp_id>/addPassword", methods=["POST"])
def add_sp_password(sp_id):
    """Add password credential to a service principal — privilege escalation vector.
    Requires Application.ReadWrite.All or Application.ReadWrite.OwnedBy scope."""
    global RUNTIME_SERVICE_PRINCIPALS
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": {"code": "Unauthorized", "message": "Bearer token required"}}), 401

    # Check token scopes — only tokens with Application.ReadWrite scope can add passwords
    try:
        claims = jwt.decode(auth[7:], options={'verify_signature': False})
        roles = claims.get('roles', [])
        scp = claims.get('scp', '')
        has_app_write = any('Application' in r and 'Write' in r for r in roles) or 'Application.ReadWrite' in scp
        if not has_app_write:
            return jsonify({'error': {'code': 'Authorization_RequestDenied',
                                      'message': 'Insufficient privileges. Token lacks Application.ReadWrite.All scope.'}}), 403
    except Exception:
        return jsonify({'error': {'code': 'Authorization_RequestDenied',
                                  'message': 'Insufficient privileges. Token lacks Application.ReadWrite.All scope.'}}), 403

    all_sps = load_service_principals()
    target_sp = next((sp for sp in all_sps if sp.get("app_id") == sp_id or sp.get("object_id") == sp_id), None)
    if not target_sp:
        return jsonify({"error": {"code": "NotFound", "message": f"Service principal {sp_id} not found"}}), 404

    new_secret = secrets.token_urlsafe(32)
    key_id = str(uuid.uuid4())
    end_date = "2099-12-31T23:59:59Z"

    with base.lock:
        # Find in runtime list or add a copy
        existing_idx = next(
            (i for i, s in enumerate(RUNTIME_SERVICE_PRINCIPALS) if s.get("app_id") == target_sp.get("app_id")), None
        )
        if existing_idx is not None:
            sp_ref = RUNTIME_SERVICE_PRINCIPALS[existing_idx]
        else:
            sp_ref = dict(target_sp)
            RUNTIME_SERVICE_PRINCIPALS.append(sp_ref)
        sp_ref.setdefault("credentials", []).append({"value": new_secret, "key_id": key_id})

    base.append_log(
        {
            "TimeGenerated": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.") + f"{random.randint(0, 9999999):07d}Z",
            "OperationName": "Add service principal credentials",
            "Category": "AuditLogs",
            "ResultType": "Success",
            "TargetResources": [{"displayName": target_sp.get("display_name", ""), "id": sp_id}],
            "InitiatedBy": _initiated_by(),
        }
    )

    return jsonify(
        {
            "secretText": new_secret,
            "keyId": key_id,
            "displayName": request.get_json(silent=True, force=True)
            .get("passwordCredential", {})
            .get("displayName", "Added by API"),
            "endDateTime": end_date,
        }
    )


# ============================================
# ADMIN ENDPOINTS
# (Used by seeder for runtime configuration)
# ============================================


@app.route("/admin/device-code-config", methods=["POST"])
def admin_device_code_config():
    """Configure what tokens the device code flow returns by scope."""
    data = request.get_json() or {}
    count = 0
    if "victim_token" in data:
        DEVICE_CODE_TOKENS["default"] = data["victim_token"]
        count += 1
    if "tokens_by_scope" in data:
        DEVICE_CODE_TOKENS.update(data["tokens_by_scope"])
        count += len(data["tokens_by_scope"])
    if count > 0:
        print(f"AD_ADMIN: Device code tokens configured ({count} scope(s): {list(DEVICE_CODE_TOKENS.keys())})")
        return jsonify({"status": "ok", "scopes": list(DEVICE_CODE_TOKENS.keys())})
    return jsonify({"error": "victim_token or tokens_by_scope required"}), 400


@app.route("/admin/service-principals", methods=["GET", "POST", "DELETE"])
def admin_service_principals():
    """
    Manage service principals at runtime.
    POST: Add/update service principals
    GET: List all service principals
    DELETE: Clear runtime service principals
    """
    global RUNTIME_SERVICE_PRINCIPALS

    if request.method == "POST":
        data = request.get_json() or {}
        # Accept either a single SP or a list
        if isinstance(data, list):
            new_sps = data
        else:
            new_sps = [data]

        with base.lock:
            for sp in new_sps:
                if not sp.get("app_id"):
                    continue
                # Check if already exists, update if so
                existing_idx = next(
                    (i for i, s in enumerate(RUNTIME_SERVICE_PRINCIPALS) if s["app_id"] == sp["app_id"]), None
                )
                if existing_idx is not None:
                    RUNTIME_SERVICE_PRINCIPALS[existing_idx] = sp
                else:
                    RUNTIME_SERVICE_PRINCIPALS.append(sp)

            result = {
                "status": "updated",
                "count": len(RUNTIME_SERVICE_PRINCIPALS),
                "service_principals": [sp.get("display_name", sp["app_id"]) for sp in RUNTIME_SERVICE_PRINCIPALS],
            }
        return jsonify(result)

    elif request.method == "DELETE":
        with base.lock:
            RUNTIME_SERVICE_PRINCIPALS = []
        return jsonify({"status": "cleared"})

    # GET
    with base.lock:
        runtime_copy = list(RUNTIME_SERVICE_PRINCIPALS)
    return jsonify({"runtime": runtime_copy, "from_config": load_service_principals()})


@app.route("/admin/validate", methods=["POST"])
def admin_validate_token():
    """Validate whether a token was issued by this Azure AD instance."""
    data = request.get_json() or {}
    token = data.get("token", "")
    if not token:
        return jsonify({"valid": False, "error": "No token provided"}), 400
    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256"], options={"verify_exp": False, "verify_aud": False})
        return jsonify({"valid": True, "claims": claims})
    except jwt.InvalidTokenError as e:
        return jsonify({"valid": False, "error": str(e)}), 401


# Register base blueprint (provides /health, /healthz, /audit/logs, /admin/reset)
app.register_blueprint(
    create_base_blueprint(
        base,
        health_extras={"tenant_id": TENANT_ID},
        include_tokens=False,
    )
)


# ---------------------------------------------------------------------------
# Phase 3: Identity Protection, OAuth credential addition, password spray
# ---------------------------------------------------------------------------

# Known risky IPs and Tor exit nodes (for IDP evaluation)
_TOR_EXIT_NODES = {"185.220.101.34", "185.220.101.42", "91.218.114.9", "198.51.100.50"}
_RISKY_COUNTRIES = {"Russia", "China", "North Korea", "Iran"}

# OAuth app credentials store
OAUTH_APP_CREDENTIALS = {}  # app_id -> [credential_entries]
RISKY_USERS = {}  # user -> {risk_level, events}


@app.route("/identity-protection/evaluate", methods=["POST"])
def idp_evaluate():
    """Evaluate a sign-in event against identity protection risk policies.

    Returns risk level and risk events based on IP, location, device compliance.
    """
    data = request.get_json(force=True)
    user = data.get("user", "unknown")
    ip = data.get("ip", "")
    location = data.get("location", {})
    is_tor = data.get("is_tor_exit", ip in _TOR_EXIT_NODES)
    device_compliant = data.get("device_compliant", True)
    country = location.get("country", "")

    risk_events = []
    risk_level = "none"

    if is_tor or ip in _TOR_EXIT_NODES:
        risk_events.append({
            "type": "anonymousIPAddress",
            "detail": f"Tor exit node {ip}",
        })
        risk_level = "high"

    if country in _RISKY_COUNTRIES:
        risk_events.append({
            "type": "unfamiliarSignInProperties",
            "detail": f"Country: {country} (atypical)",
        })
        risk_level = "high" if risk_level != "high" else risk_level

    if not device_compliant:
        risk_events.append({
            "type": "nonCompliantDevice",
            "detail": "Device not Intune-compliant",
        })
        if risk_level == "none":
            risk_level = "medium"

    if not risk_events:
        risk_level = "none"

    action = "block" if risk_level == "high" else "mfa" if risk_level == "medium" else "allow"

    # Track risky users
    if risk_level in ("high", "medium"):
        RISKY_USERS[user] = {"risk_level": risk_level, "events": risk_events}

    # Emit AADUserRiskEvents log
    base.append_log({
        "CreationTime": datetime.now(UTC).isoformat(),
        "Operation": "UserRiskEvaluation",
        "Workload": "AzureActiveDirectory",
        "UserId": user,
        "RiskLevel": risk_level,
        "RiskEvents": risk_events,
        "IpAddress": ip,
        "Location": location,
        "Action": action,
        "_source": "azure_ad",
    })

    return jsonify({
        "risk_level": risk_level,
        "risk_events": risk_events,
        "action": action,
    })


@app.route("/identity-protection/risky-users", methods=["GET"])
def idp_risky_users():
    """List users flagged as risky."""
    return jsonify({"risky_users": RISKY_USERS})


@app.route("/oauth-apps/<app_id>/credentials", methods=["POST"])
def add_oauth_credential(app_id):
    """Add a credential to an OAuth application (persistence technique T1098.001).

    Emits AuditLogs (Operation: Add service principal credentials).
    """
    data = request.get_json(force=True)
    cred_type = data.get("credential_type", "password")
    display_name = data.get("display_name", "")
    source_user = data.get("source_user", "unknown")

    cred_entry = {
        "id": f"cred-{len(OAUTH_APP_CREDENTIALS.get(app_id, [])) + 1:03d}",
        "type": cred_type,
        "display_name": display_name,
        "app_id": app_id,
        "added_by": source_user,
    }

    OAUTH_APP_CREDENTIALS.setdefault(app_id, []).append(cred_entry)

    base.append_log({
        "TimeGenerated": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.") + f"{random.randint(0, 9999999):07d}Z",
        "CreationTime": datetime.now(UTC).isoformat(),
        "OperationName": "Add service principal credentials",
        "Operation": "Add service principal credentials",
        "Category": "AuditLogs",
        "Workload": "AzureActiveDirectory",
        "ResultStatus": "Success",
        "ResultType": "Success",
        "UserId": source_user,
        "InitiatedBy": source_user,
        "TargetResources": [{"Id": app_id, "DisplayName": display_name}],
        "_event_type": "oauth_credential_add",
        "_source": "azure_ad",
    })

    return jsonify(cred_entry)


@app.route("/auth/password-spray", methods=["POST"])
def password_spray():
    """Bulk authentication attempts — generates failed sign-in events (T1110.003).

    Cloud-side password spray. Each attempt emits a real SigninLogs-shaped row
    with ``ResultType: "50126"`` (invalid credentials) — the distinctive marker a
    hunt over SigninLogs keys on for spray detection. Uses the canonical sign-in
    log generator so the row lands in the SigninLogs ``ResultType`` column (an
    ad-hoc OfficeActivity-shaped row would bury the code and miss the hunt).
    """
    data = request.get_json(force=True)
    targets = data.get("targets") or ([data["target"]] if data.get("target") else [])
    if not targets:
        targets = ["unknown@contoso.com"]
    source_ip = data.get("source_ip") or attacker_source_ip(base)

    results = []
    for target in targets:
        generate_azure_signin_log(
            result_type="Failure",
            result_description="Invalid username or password or Invalid on-premise username or password.",
            client_id="",
            app_display_name="Office 365",
            ip_address=source_ip,
            user_principal_name=target,
            is_interactive=True,
            error_code=50126,  # invalid credentials (password spray signature)
            authentication_requirement="singleFactorAuthentication",
        )
        results.append({"user": target, "result": "failed"})

    return jsonify({"results": results, "total": len(results)})


if __name__ == "__main__":
    print(f"Starting Azure AD mock for tenant {TENANT_ID}")
    app.run(host="0.0.0.0", port=8080)
