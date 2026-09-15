# CTI-REALM: Cyber Threat Intelligence Detection Rule Development Benchmark

CTI-REALM (Cyber Threat Real World Evaluation and LLM Benchmarking) evaluates AI agents' ability to interpret threat intelligence and develop detection rules. The benchmark provides a realistic environment replicating the security analyst workflow, enabling agents to examine CTI reports, execute queries, understand schema structures, and construct detection rules.

This is the SABER port of the [inspect_evals CTI-REALM benchmark](https://github.com/UKGovernmentBEIS/inspect_evals).

See [SABER versus Inspect native](README_SABER_VS_OSS.md) for the main differences and the reasons behind this integration.

## Overview

CTI-REALM tests an AI agent's capability across a 5-stage detection engineering workflow:

1. **CTI Report Analysis** — Retrieve and analyze relevant threat intelligence reports
2. **MITRE Technique Mapping** — Identify relevant ATT&CK techniques from threat intelligence
3. **Data Source Discovery** — Explore available Kusto data sources dynamically
4. **KQL Development** — Write and test queries against real telemetry data
5. **Detection Rule Generation** — Produce Sigma rules and validated KQL queries

Evaluation involves emulated attacks of varying complexity across Linux systems, cloud platforms, and Azure Kubernetes Service (AKS). Agent performance is measured through both final detection results and trajectory-based rewards that capture decision-making effectiveness.

## Setup

### Prerequisites

- Docker (required for the containerized evaluation environment)
- At least 4GB available RAM for Docker containers
- [SABER framework](../../README.md) installed (`uv sync --all-extras` from workspace root)

### Docker Image Sizes

The evaluation requires approximately **6.5 GB** of Docker images:

| Image | Size | Purpose |
|---|---|---|
| `kustainer-linux` | ~4.5 GB | Azure Data Explorer emulator (Kusto) |
| `saber/cti_realm/sandbox` | ~1.7 GB | Main evaluation environment |
| `python:3.11-slim` | ~190 MB | Init services (kusto-init, mitre-service) |

First-run startup takes several minutes as images are pulled and data is loaded into Kusto.

### Download Data

All data is hosted on Hugging Face at [`arjun180-new/cti_realm`](https://huggingface.co/datasets/arjun180-new/cti_realm). Data is downloaded automatically by the `DownloadCTIData` setup hook when running an evaluation for the first time. The hook downloads:

1. **Dataset files** (to `data/`) — Detection objectives, sample metadata, and ground truth answers
2. **Kusto telemetry data** (to `docker/kusto_init/data/`) — 12 log sources including endpoint, AKS, cloud, identity, and application telemetry
3. **CTI reports** (to `data/cti_reports/`) — Threat intelligence reports for analysis
4. **Sigma rules** (to `data/sigma_rules.json`) — Reference detection rule collection

Task YAML files are then auto-generated from the downloaded JSONL datasets by the `GenerateTaskYAML` setup hook.

### Troubleshooting

If you see this error when running the evaluation:

```text
fork/exec /usr/local/lib/docker/cli-plugins/docker-buildx: no such file or directory
Failed to build docker containers
```

This means Docker Desktop is not running. Start Docker Desktop before running the evaluation.

## Architecture

The evaluation environment is a containerized Docker system integrated with [SABER](../../README.md) and [Inspect AI](https://inspect.aisi.org.uk/) that provides:

- **CTI Repository** — 37 source reports from Microsoft Security, Datadog Security Labs, Palo Alto Networks, and Splunk Security Content
- **Kusto Cluster** — Query engine for executing KQL against telemetry data
- **Telemetry Logs** — Multi-source security logs from attack simulations across Linux endpoints, AKS clusters, and Azure cloud
- **MITRE ATT&CK Database** — Techniques and tactic mappings for threat contextualization
- **Sigma Rules Database** — Reference collection of existing detection rules
- **Tool API** — 9 specialized functions for CTI retrieval, data exploration, query execution, threat context mapping, and output validation

### Domain Structure

```
cti_realm/
├── cti_realm.py          # Domain entry point (Inspect AI task definition)
├── eval.yaml             # Domain metadata and Docker image config
├── setup.py              # Setup hooks (HF download + task YAML generation)
├── compose/              # Docker Compose files (includes service health checks)
├── docker/               # Dockerfiles and init scripts
├── prompts/              # Jinja2 prompt templates
│   ├── instructions/     # Agent instruction prompts
│   ├── assistants/       # Assistant prompts
│   └── judge/            # LLM-as-judge evaluation prompts
├── scoring/              # Scoring strategies and checkpoint logic
│   ├── strategies.py     # SABER scoring strategy implementations
│   ├── _trajectory.py  # C0–C3 trajectory checkpoint functions
│   ├── _kql.py           # C4 KQL F1-score evaluation
│   ├── _sigma.py         # C4 Sigma rule quality evaluation
│   └── _parsing.py       # Text parsing utilities
├── scripts/              # Task YAML generation from JSONL
├── tasks/                # Generated task YAML files
│   ├── cti_realm_25/     # 25-sample balanced subset
│   └── cti_realm_50/     # 50-sample full evaluation
├── tools/                # MCP tools exposed to agents
│   ├── cti.py            # CTI report retrieval
│   ├── kql.py            # Kusto query tools
│   ├── mitre.py          # MITRE ATT&CK lookup
│   ├── sigma.py          # Sigma rule tools
│   └── validation.py     # Input validation
├── tests/                # Test suite
└── data/                 # Downloaded data (auto-populated)
```

## Usage

### Dataset Variants

| Dataset | Samples | Description |
|---|---|---|
| `cti_realm_25` | 25 | Stratified subset (15 Linux, 6 AKS, 4 Cloud) |
| `cti_realm_50` | 50 | Full evaluation (25 Linux, 17 AKS, 8 Cloud) |

CTI-REALM-25 is a subset of CTI-REALM-50, so the two dataset variants contain 50 unique scenarios in total. All variants use hard difficulty (minimal prompting, no workflow guidance).

### Running Evaluations

```bash
# Run 25-sample benchmark
uv run inspect eval domains/cti_realm --model openai/gpt-4o -T dataset=cti_realm_25

# Run 50-sample benchmark
uv run inspect eval domains/cti_realm --model openai/gpt-4o -T dataset=cti_realm_50

# Run with limited samples
uv run inspect eval domains/cti_realm --model openai/gpt-4o -T dataset=cti_realm_25 --limit 5

# Build Docker images on first run
uv run inspect eval domains/cti_realm --model openai/gpt-4o -T dataset=cti_realm_25 -T build=true
```

### Notes

- Use `--max-samples 2` for stable performance when running multiple samples
- The default task configuration sets a 70-tool-call budget, not 70 messages; see [execution differences](README_SABER_VS_OSS.md#execution-differences)
- Docker Required: Ensure Docker is running as the benchmark uses containerized services
- At least 4GB available RAM recommended for Docker containers

## Scoring

CTI-REALM uses a trajectory-based evaluation framework combining deterministic checkpoints with LLM-as-judge assessment. The total reward is:

$$R_{\text{total}} = \sum_{i \in \{C0, C1, C2, C3, C4\}} w_i \cdot r_i \in [0, 1]$$

### Checkpoints

| Checkpoint | Weight | Method | Description |
|---|---|---|---|
| C0 — CTI Analysis | 0.125 | LLM-as-judge | Correct identification of relevant threat intelligence reports |
| C1 — MITRE Mapping | 0.075 | Expected-technique coverage | Coverage of expected ATT&CK technique IDs |
| C2 — Data Exploration | 0.100 | Jaccard similarity | Identification of relevant telemetry sources |
| C3 — Query Execution | 0.050 | Binary | At least 2 unique queries with nonempty successful results |
| C4 — Detection Quality | 0.650 | F1-score + LLM-as-judge | KQL correctness via F1-score, Sigma rule quality via judge |

Checkpoints C0–C3 comprise 35% of the total weight (trajectory reward), while C4 accounts for 65% (ground truth reward).

### Grader Model

Checkpoints C0 and C4 use an LLM-as-judge, defaulting to `openai/azure/gpt-5-mini`. The current SABER custom scorers resolve their configured/default model directly rather than the upstream `grader` model role. Passing a `grader` role does not override these scorers.
