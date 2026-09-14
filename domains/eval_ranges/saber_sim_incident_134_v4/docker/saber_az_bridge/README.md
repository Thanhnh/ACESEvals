# SABER Az Bridge

SABER Az Bridge is a SABER-Sim mock implementation of the `az` executable for
Linux sandbox containers. It is intentionally separate from the legacy
`resources/mock_services/az_cli` state-file mock.

The bridge is scoped to resources simulated by SABER-Sim bundles. It combines:

- scenario state from `inputs/az_initial_state.json`
- scenario metadata from `base_infrastructure.yaml`
- live mock-service endpoints when available

It is not a full Azure CLI replacement. Unsupported commands fail loudly with
Azure CLI-style command-group errors.

## Installation in containers

Exported SABER docker scaffolding copies this directory to
`/opt/saber-az-bridge` and creates `/usr/local/bin/az`.

For local testing:

```bash
PYTHONPATH=resources/mock_clients/saber_az_bridge \
AZ_BRIDGE_BACKEND=state \
AZ_BRIDGE_INITIAL_STATE=generated/blob_storage_attack_bundle/inputs/az_initial_state.json \
AZ_BRIDGE_BASE_INFRASTRUCTURE=generated/blob_storage_attack_bundle/base_infrastructure.yaml \
python -m saber_az_bridge account show
```

## Important environment variables

| Variable | Purpose |
| --- | --- |
| `AZ_BRIDGE_INITIAL_STATE` | Immutable initial scenario state. |
| `AZ_BRIDGE_STATE` | Mutable per-run state file. |
| `AZ_BRIDGE_BASE_INFRASTRUCTURE` | Scenario infrastructure metadata. |
| `AZ_BRIDGE_BACKEND` | `hybrid` (default), `state`, or `live`. |
| `AZURE_CONFIG_DIR` | Local Azure CLI-compatible config/cache directory. |
| `AZ_BRIDGE_AAD_URL` | Azure AD mock base URL. |
| `AZ_BRIDGE_ARM_URL` | ARM mock base URL. |
| `AZ_BRIDGE_KEYVAULT_URL` | Key Vault mock base URL. |
| `AZ_BRIDGE_IMDS_URL` | IMDS mock base URL. |
| `AZ_BRIDGE_EVENTGRID_URL` | Event Grid mock base URL; defaults to `http://eventgrid:4000`. |
| `AZ_BRIDGE_FUNCTIONS_URL` | Functions mock base URL. |
| `AZ_BRIDGE_STORAGE_BLOB_URL` | Storage/Azurite base URL. |

## Supported command areas

| Area | Examples | Backend |
| --- | --- | --- |
| General/account | `az --version`, `az login`, `az logout`, `az account show/list/set/clear/get-access-token/list-locations` | State plus AAD/IMDS when available |
| Config/cloud | `az configure --defaults`, `az config set/get/param-persist`, `az cloud show/list/set/register/update/unregister` | State |
| ARM/resource groups | `az group list/show`, `az resource list/show/update --set` | State, with generated resource normalization |
| Entra ID | `az ad user/group/sp/app list/show`, group membership, app/SP credentials, app permissions, federated credentials, selected Microsoft Graph `az rest` discovery paths | State |
| RBAC | `az role assignment list/create/delete`, `az role definition list` | State |
| Key Vault | `az keyvault list/show/update`, `az keyvault secret/key/certificate list/show`, secret set/delete, policies, network rules | Hybrid: live Key Vault if available, state fallback in hybrid mode |
| Storage | `az storage account list/show/update`, keys, containers, blobs | State; blob data is represented in bridge state |
| Network | NSGs/rules, VNets/subnets, private endpoints, private DNS zone/link creation | State |
| App Service/Functions | `az webapp ...`, `az functionapp ...`, managed identity show, config/auth show, app settings, function list | State plus Functions admin endpoint when available |
| Event Grid | topics and event-subscriptions | Hybrid: live Event Grid when available, state fallback |
| Front Door/WAF | `az afd profile/endpoint ...`, `az afd waf-policy list` | State/base infrastructure |
| AKS | `az aks list/show/get-credentials/command invoke` | State only when clusters are present |
| Security/Policy/Monitor/Locks | Defender pricing and assessment list/show/create/delete, subscription diagnostic settings, selected policy/monitor/lock compatibility commands | State plus posture-derived Defender assessment defaults |

Unsupported commands fail with Azure CLI-style command-group errors instead of silently succeeding.

In `hybrid` mode, account, group, generic resource, storage account, Key Vault,
Web App, Function App, and AKS list/show-style discovery prefers the live ARM
mock when a token from `az login` is available, then falls back to generated
state if the live endpoint is not reachable. Generic resource discovery first
tries the subscription resources endpoint and then provider-specific endpoints.
Key Vault secret operations, Function admin listing, and Event Grid subscription
management use their live mock service endpoints when available.

## Docker-backed hybrid tests

The integration suite can start an isolated Docker Compose project with the real
SABER mock services and generated storage infrastructure: Azure AD, ARM, IMDS,
Key Vault, Functions, Event Grid, Azurite/blob proxy, App Service, Front
Door/WAF, Gateway, Domain Controller, Exchange Online, Kubernetes API, AKS pod,
and Azure Sentinel:

```bash
SABER_RUN_DOCKER_TESTS=1 \
python -m pytest -o addopts='' tests/integration/test_saber_az_bridge_hybrid.py -q -s
```

The tests publish mock service ports on ephemeral host ports and use a unique
Compose project name, then tear the project down with volumes after completion.

## Export integration

Reconnaissance `export-saber` bundles copy this client into exported bundles at
`docker/saber_az_bridge/` and into
`domain_scaffolding/docker/saber_az_bridge/`. The generated sandbox Dockerfile
copies it to `/opt/saber-az-bridge`, creates `/usr/local/bin/az`, and puts
`/usr/local/bin` before `/usr/bin` so the bridge shadows the real Azure CLI.
