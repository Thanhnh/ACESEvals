# ACES — Agent Capability Evaluation Suite

> **Naming:** The external name for this project is **ACES** (Agent Capability Evaluation Suite). **SABER** (Security Agent Benchmarking and Evaluation Research) is the internal Microsoft codename. Both names refer to the same system. You may see "SABER" in code, package names (`saber`), CLI commands (`uv run saber build`), and logs — this is expected.

<!-- ADO-ONLY:START — strip this banner when syncing to GitHub (ACESEvals is the permanent home, not deprecated) -->
> ## ⚠️ Repository migration — this Azure DevOps repo is being retired
>
> **`oss_saber` (Azure DevOps) and its library `SABER` are being discontinued.** Development is
> moving to GitHub, which is now the **permanent home**:
>
> - Benchmarks: **[github.com/microsoft/ACESEvals](https://github.com/microsoft/ACESEvals)** — replaces `oss_saber`
> - Library: **[github.com/microsoft/ACES](https://github.com/microsoft/ACES)** — replaces `SABER`
>
> **Please migrate your clones and remotes to GitHub by September 30, 2026.** After that date the
> Azure DevOps `oss_saber` and `SABER` repos will be frozen (read-only) and then removed. All new
> work, issues, and pull requests should go to the GitHub repos.
<!-- ADO-ONLY:END -->

A thin Python library for benchmarking AI security agents using YAML-driven task definitions and the [inspect_ai](https://inspect.ai-safety-institute.org.uk/) evaluation framework. No server, no client — just `inspect eval`.

## Architecture

```
YAML task configs  →  saber  →  inspect_ai Task  →  inspect eval
     (data)          (library)     (native engine)      (CLI)
```

SABER loads YAML task definitions, renders Jinja2 prompts, and produces native inspect_ai `Task` objects. Docker sandboxes, tool execution, scoring, and agent loops are all handled by inspect_ai's built-in primitives.

```
┌──────────────────────────────────────────────────────────────────┐
│  inspect eval domains/excytin --model openai/gpt-4.1            │
│                                  -T agent=react                 │
│                                                                  │
│  ┌────────────────┐   ┌──────────────────────────────────────┐  │
│  │ domains/excytin│   │ inspect_ai (native)                  │  │
│  │                │   │                                      │  │
│  │  excytin.py    │──▶│  Task(dataset, solver, scorer,       │  │
│  │  (@task)       │   │        sandbox=("saber", ...))       │  │
│  │                │   │                                      │  │
│  └───────┬────────┘   │  SaberSandboxEnvironment (subclass)  │  │
│          │            │  react() / copilot / claude_code     │  │
│          ▼            │  bash() / python() tools             │  │
│  ┌───────────────┐    │  model_graded_qa() scorer            │  │
│  │ saber library │    └──────────────────────────────────────┘  │
│  │               │                                              │
│  │ agents/       │ ← AgentRegistry: -T agent=<name> switching   │
│  │ config/       │ ← Loads YAML, merges inheritance             │
│  │ scoring/      │ ← @scorer: submission + subtask checkpoints  │
│  │ prompts/      │ ← Jinja2 → AgentPrompt                      │
│  │ tools/        │ ← @tool wrappers for SQL, KQL, etc.         │
│  │ approval/     │ ← Security approval via native Approver      │
│  └───────────────┘                                              │
└──────────────────────────────────────────────────────────────────┘
```

---

## Repositories

GitHub is the **permanent home** for this project. The Azure DevOps mirrors are deprecated and
will be frozen (read-only) after **September 30, 2026**.

| | GitHub (permanent home) | Azure DevOps (deprecated) |
|---|---|---|
| **Benchmarks** (this repo) | [ACESEvals](https://github.com/microsoft/ACESEvals) | [oss_saber](https://dev.azure.com/MSECAIModels/Benchmarking/_git/oss_saber) *(retiring)* |
| **Library** (saber package) | [ACES](https://github.com/microsoft/ACES) | [SABER](https://dev.azure.com/MSECAIModels/Benchmarking/_git/SABER) *(retiring)* |

`saber` and `inspect-ai` are installed from the GitHub repos — see `[tool.uv.sources]` in
`pyproject.toml`. No per-repository source switching is required.

---

## Quick Start

### Prerequisites

- **Docker** (with Docker Compose v2)
- **Python 3.11–3.12**
- **uv** package manager
- **Azure OpenAI** or compatible LLM endpoint

> **Sandbox images.** SABER builds two and picks between them automatically from
> `-T agent=`, so there is nothing to configure:
>
> 1. **Default (`react`)** → `saber/sandbox:latest` (~320MB): Python only. Builds even
>    where corporate policy blocks container access to `registry.npmjs.org`.
> 2. **`-T agent=copilot` / `-T agent=claude_code`** → `saber/sandbox:agents` (~2.9GB):
>    adds Node and the agent CLIs. Domain images are rebuilt automatically when the
>    selected agent needs a different variant.
> 3. **Restricted networks** → if container builds cannot reach npm/PyPI, vendor the
>    artifacts from a host that can and rebuild; the build falls back to them:
>    ```bash
>    # only needed for mode 2 - script ships with the installed saber package
>    "$(uv run python -c 'import saber,pathlib;print(pathlib.Path(saber.__file__).parent/"environments/_dockerfiles")')/fetch_npm.sh"
>    domains/<domain>/docker/fetch_wheels.sh   # if PyPI's CDN is blocked too
>    ```

### Installation

```bash
# Clone the repository
git clone https://github.com/microsoft/ACESEvals.git
cd ACESEvals

# Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh
source $HOME/.local/bin/env

# Install all dependencies (saber + inspect-ai are fetched from GitHub; see pyproject.toml)
uv sync --all-extras

# Configure LLM credentials
cp .env.template .env
# Edit .env with your credentials:
#   AZUREAI_OPENAI_API_KEY=your-key-here
#   AZUREAI_OPENAI_BASE_URL=https://your-endpoint.openai.azure.com
#   AZUREAI_OPENAI_API_VERSION=2024-12-01-preview
```

### Run Your First Evaluation

```bash
# List available domains and tasks
uv run inspect list tasks

# Evaluate with default react agent (uses the domain's default dataset)
uv run inspect eval domains/excytin --model openai/azure/gpt-4.1

# Select a specific dataset
uv run inspect eval domains/excytin --model openai/azure/gpt-4.1 \
  -T dataset=legacy_test_set

# Further filter within a dataset
uv run inspect eval domains/excytin --model openai/azure/gpt-4.1 \
  -T dataset=latest_test_set -T task_filter="incident_5*"

# Use a different agent
uv run inspect eval domains/excytin --model openai/azure/gpt-4.1 \
  -T agent=copilot
```

> **Reasoning models — pass `--reasoning-effort` explicitly.** Reasoning models (gpt-5.x,
> o1/o3, Claude Opus) do **no reasoning by default** here — `reasoning_effort` unset means
> 0 reasoning tokens and materially lower scores. For example, excytin `gpt-5.4` on
> `latest_test_set` scored **0.813** with reasoning unset vs **0.886** with
> `--reasoning-effort high` (+0.073). Always set it for reproducible, apples-to-apples runs:
>
> ```bash
> uv run inspect eval domains/excytin --model openai/azure/gpt-5.4 --reasoning-effort high
> ```

---

## Available Domains

### Excytin — Incident Response

Cybersecurity incident response with database forensics and SQL analysis across 8 security incidents.

| Task Set | Count | Description |
|----------|-------|-------------|
| `latest_test_set` | 599 | O3-generated test questions — **use for benchmarking** |
| `latest_train_set` | 418 | O3-generated training questions — **use for fine-tuning** |
| `latest_cleaned_test_set` | 599 | Opus-5–regenerated test set |
| `latest_cleaned_train_set` | 418 | Opus-5–regenerated training set |
| `legacy_test_set` | 589 | O1-preview questions — paper comparison only |
| `legacy_train_set` | 418 | O1-preview questions — paper comparison only |

**Default dataset:** `latest_test_set` — running without `-T dataset` automatically selects this set.

> **First run:** Excytin data (`csv_files/` and `sql_files/`) is automatically downloaded from [HuggingFace](https://huggingface.co/datasets/anandmudgerikar/excytin-bench) on first run. No manual setup needed — the setup hook fetches and extracts `data.zip` (~280 MB) into `domains/excytin/data/`. To force re-download: `-T force_download=true`.

```bash
# Latest test set (default — no flag needed)
uv run inspect eval domains/excytin --model openai/azure/gpt-4.1

# Specific dataset
uv run inspect eval domains/excytin --model openai/azure/gpt-4.1 \
  -T dataset=legacy_test_set

# Dataset + task filter for a specific incident
uv run inspect eval domains/excytin --model openai/azure/gpt-4.1 \
  -T dataset=latest_test_set -T task_filter="incident_5*"

# Quick test (limit samples)
uv run inspect eval domains/excytin --model openai/azure/gpt-4.1 --limit 10
```

#### Insane Mode

Excytin supports an **insane mode** (`-T mode=insane`) that removes four key alert and incident signal tables from the database:

| Removed Table | Purpose |
|---------------|---------|
| `SecurityAlert` | Pre-computed security alert records (rule-based, ML-based, expert-curated detections) |
| `AlertEvidence` | Evidence artifacts linked to alerts (files, IPs, accounts, processes) |
| `AlertInfo` | Lightweight alert metadata (category, severity, detection source) |
| `SecurityIncident` | Incident grouping, classification, ownership, and linked alert IDs |

These four tables encode **all rule-based, ML-based, and expert security domain knowledge** that a human SOC analyst would normally rely on to triage and investigate incidents. Removing them forces the agent to reason entirely from raw telemetry logs (Device events, Sign-in logs, Email events, Network events, etc.) — effectively recreating the alert detection pipeline from scratch.

**Why "insane"?** This task would be practically impossible for a human analyst who relies on alert signals to parse through the massive volume of raw logs. For an AI agent, however, this tests whether it can derive security insights without any pre-computed intelligence — a fundamentally harder capability evaluation.

```bash
# Run insane mode
uv run inspect eval domains/excytin --model openai/azure/gpt-4.1 \
  -T mode=insane

# Insane mode with task filtering
uv run inspect eval domains/excytin --model openai/azure/gpt-4.1 \
  -T mode=insane -T task_filter="incident_5*"

# Insane mode with specific dataset
uv run inspect eval domains/excytin --model openai/azure/gpt-4.1 \
  -T mode=insane -T dataset=latest_test_set

# Compare normal vs insane on same tasks
uv run inspect eval domains/excytin --model openai/azure/gpt-4.1 \
  -T task_filter="incident_5_1" --limit 1
uv run inspect eval domains/excytin --model openai/azure/gpt-4.1 \
  -T mode=insane -T task_filter="incident_5_1" --limit 1
```

> **How it works:** A setup hook generates `incident_X_insane.sql` files by stripping the four table definitions and data-load statements from the original SQL init scripts. A separate Docker Compose file (`compose/all_incidents_insane.compose.yml`) mounts these stripped SQL files. The generated `_insane.sql` files are cached and only regenerated when the source SQL files change.

### CTI Realm — Cyber Threat Intelligence

Threat intelligence analysis and detection rule development with KQL, MITRE ATT&CK mapping, and Sigma rules — 100 detection scenarios.

| Dataset | Count | Description |
|---------|-------|-------------|
| `cti_realm_25` | 25 | Core detection scenarios — **default** |
| `cti_realm_75` | 75 | Extended detection set |

```bash
# Default dataset (cti_realm_25)
uv run inspect eval domains/cti_realm --model openai/azure/gpt-4.1

# Full 75-task set
uv run inspect eval domains/cti_realm --model openai/azure/gpt-4.1 \
  -T dataset=cti_realm_75

# Dataset + task filter
uv run inspect eval domains/cti_realm --model openai/azure/gpt-4.1 \
  -T task_filter="linux_*"
```

### CRSBench — Vulnerability Patching

Vulnerability patching benchmark — agent receives vulnerable source code and crash-triggering proof-of-vulnerability inputs, must write patches. Data is automatically downloaded from HuggingFace on first run.

```bash
# All benchmarks
uv run inspect eval domains/crsbench --model openai/azure/gpt-4.1

# Download and run a specific benchmark only
uv run inspect eval domains/crsbench --model openai/azure/gpt-4.1 \
  -T dataset=afc-curl-delta-01
```

> `-T dataset` also scopes the HuggingFace download — only the selected benchmark's data is fetched.

### CyBench — Security Challenges

CTF-style cybersecurity challenges for penetration testing and web security evaluation.

```bash
uv run inspect eval domains/cybench --model openai/azure/gpt-4.1

# Filter to specific challenges
uv run inspect eval domains/cybench --model openai/azure/gpt-4.1 \
  -T task_filter="labyrinth_*"
```

---

## Agents

SABER supports three agent implementations, switchable via `-T agent=<name>`:

| Agent | Flag | Description |
|-------|------|-------------|
| **react** | `-T agent=react` | Default. Wraps inspect_ai's built-in `react()` loop. Runs in-process. |
| **copilot** | `-T agent=copilot` | GitHub Copilot SDK agent. Runs inside the Docker sandbox via bridge proxy. |
| **claude_code** | `-T agent=claude_code` | Claude Code CLI agent. Runs inside the Docker sandbox via bridge proxy. |

### React Agent (Default)

The react agent uses inspect_ai's native `react()` solver with SABER prompt injection. No special setup required.

```bash
uv run inspect eval domains/excytin --model openai/azure/gpt-4.1 -T agent=react
```

### GitHub Copilot Agent

The Copilot agent runs the [Copilot SDK](https://docs.github.com/en/copilot) Python client inside the Docker sandbox. A bridge proxy routes all LLM traffic back through inspect_ai's configured model provider.

#### Prerequisites

The `copilot` Python package must be installed **inside the sandbox Docker image**. The host machine does not need the Copilot SDK — only the sandbox container.

#### How It Works

1. SABER writes a runner script into the sandbox at `/tmp/_copilot_runner.py`
2. A local bridge proxy starts on a free port, forwarding LLM calls to inspect_ai
3. The runner starts `CopilotClient` with BYOK (bring-your-own-key) provider pointed at the proxy
4. All model traffic flows: sandbox → bridge proxy → inspect_ai model → LLM provider
5. Custom SABER tools (SQL, KQL, etc.) are exposed via MCP; `bash` and `python` are native to Copilot

#### Configuration

All parameters are passed as `-T` flags:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `persona_file` | None | Path to agent persona markdown file (YAML frontmatter + body) |
| `skills_dir` | None | Path to skills directory — uploaded into sandbox at `.github/skills/` |
| `timeout` | 300 | Runner timeout in seconds |
| `max_steps` | 50 | Maximum tool calls before forced completion |
| `port_base` | 3000 | Starting port for bridge proxy |

```bash
# Basic copilot evaluation
uv run inspect eval domains/excytin --model openai/azure/gpt-4.1 \
  -T agent=copilot

# With persona and skills
uv run inspect eval domains/excytin --model openai/azure/gpt-4.1 \
  -T agent=copilot \
  -T persona_file=path/to/persona.md \
  -T skills_dir=path/to/skills/

# With custom timeout and step limit
uv run inspect eval domains/excytin --model openai/azure/gpt-4.1 \
  -T agent=copilot \
  -T timeout=600 \
  -T max_steps=100
```

#### Persona File Format

Persona files use YAML frontmatter with a markdown body:

```markdown
---
name: Security Analyst
description: Expert incident responder
---

You are a cybersecurity incident response specialist.
Focus on database forensics and SQL-based investigation.
```

### Claude Code Agent

The Claude Code agent runs the [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code) binary (`claude`) inside the Docker sandbox. A bridge proxy routes all model calls back through inspect_ai.

#### Prerequisites

The `claude` CLI binary must be installed **inside the sandbox Docker image**. Auth is handled automatically — SABER writes a settings file that routes API calls through the bridge proxy.

#### How It Works

1. SABER resolves the `claude` binary inside the sandbox (auto-detection or explicit path)
2. Auth is seeded via `~/.claude/settings.json` with an API key helper
3. A local bridge proxy starts, forwarding all Anthropic API calls to inspect_ai
4. Claude Code runs with `--print --output-format stream-json --verbose`
5. All model traffic flows: sandbox → bridge proxy → inspect_ai model → LLM provider
6. Custom SABER tools (SQL, KQL, etc.) are exposed via MCP; `bash` and `python` are native to Claude Code

#### Configuration

All parameters are passed as `-T` flags:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `persona_file` | None | Path to persona file — content passed as `--append-system-prompt` |
| `skills_dir` | None | Path to skills directory — uploaded into sandbox at `.claude/skills/`, added via `--add-dir` |
| `version` | `"auto"` | Claude binary path or `"auto"` to search `PATH` |
| `disallowed_tools` | `[]` | Tool names to disallow via `--disallowed-tools` |
| `timeout` | 300 | Execution timeout in seconds |
| `max_steps` | 50 | Maximum tool calls before forced completion |

```bash
# Basic claude_code evaluation
uv run inspect eval domains/excytin --model openai/azure/gpt-4.1 \
  -T agent=claude_code

# With persona and skills
uv run inspect eval domains/excytin --model openai/azure/gpt-4.1 \
  -T agent=claude_code \
  -T persona_file=path/to/persona.md \
  -T skills_dir=path/to/skills/

# With explicit binary path and tool restrictions
uv run inspect eval domains/excytin --model openai/azure/gpt-4.1 \
  -T agent=claude_code \
  -T version=/usr/local/bin/claude \
  -T disallowed_tools="WebFetch,NotebookEdit"
```

### Agent Architecture: Sandbox Bridge Pattern

Both copilot and claude_code use a **sandbox bridge** pattern:

```
┌─────────────────────┐     ┌─────────────────────┐
│  Docker Sandbox     │     │  Host (inspect_ai)   │
│                     │     │                      │
│  Agent CLI/SDK      │────▶│  Bridge Proxy        │
│  (copilot/claude)   │     │  (localhost:port)    │
│                     │     │         │            │
│  bash, python       │     │         ▼            │
│  (native tools)     │     │  inspect_ai Model    │
│                     │     │         │            │
│  SABER MCP tools    │◀───│  MCP Tool Server     │
│  (bridged)          │     │  (sql, kql, etc.)   │
└─────────────────────┘     └─────────────────────┘
```

- **Native tools** (`bash`, `python`) run directly inside the sandbox — the agent handles these natively
- **SABER tools** (domain-specific like `sql_query`, `kql_query`) are bridged via MCP
- **Model calls** are proxied back to inspect_ai's configured model provider
- **Tool call limits** are enforced via a custom `GenerateFilter` on the bridge

> **Note:** Agent `-T` parameters like `persona_file` and `skills_dir` only flow through to the agent if the domain's `@task` function forwards `**kwargs` to `create_task()`. Currently CRSBench does this by default. Other domains accept explicit parameters — check each domain's entry point.

---

## Task Parameters (`-T` Flags)

All parameters are passed via `inspect eval -T key=value`:

### Core Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `dataset` | From `global.yaml` | Select a named task group (preferred over `task_filter` for known sets) |
| `task_filter` | None | Glob or comma-separated task name filter (applied after `dataset`) |
| `agent` | `"react"` | Agent: `react`, `copilot`, `claude_code` |
| `mode` | None | Evaluation mode. Excytin supports `"insane"` (strips alert/incident tables) |
| `rebuild` | None | `"true"` = all images, `"name1,name2"` = specific images |
| `run_preflight` | `false` | Validate compose files before evaluation |
| `keep_permanent` | `false` | Keep permanent Docker services alive after eval |

> **`dataset` vs `task_filter`:** Each domain defines a `default_dataset` in `global.yaml` — running without `-T dataset` uses that default. Use `-T dataset` to switch between known task groups (e.g., `latest_test_set` vs `legacy_test_set`). Use `-T task_filter` only when you need to narrow down to specific tasks by name pattern. Both can be combined: dataset filters first, then task_filter narrows further.

### Docker Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `sandbox_compose` | `compose/sandbox.compose.yml` | Sandbox compose file (relative to domain) |
| `permanent_compose` | None | Permanent services compose file |
| `permanent_project` | `saber-permanent` | Docker Compose project name for permanent services |

### Agent Parameters (forwarded to agent factory)

| Parameter | Agents | Default | Description |
|-----------|--------|---------|-------------|
| `persona_file` | copilot, claude_code | None | Path to persona markdown file |
| `skills_dir` | copilot, claude_code | None | Path to skills directory |
| `timeout` | copilot, claude_code | 300 | Execution timeout (seconds) |
| `max_steps` | copilot, claude_code | 50 | Max tool calls before forced completion |
| `port_base` | copilot | 3000 | Bridge proxy starting port |
| `version` | claude_code | `"auto"` | Claude binary path |
| `disallowed_tools` | claude_code | `[]` | Tools to disallow |

### Scoring Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `score_aggregation` | From YAML | Override: `average`, `weighted_sum`, or `max` |

---

## SABER CLI

Operational commands for Docker environments:

```bash
# Build Docker images for a domain
uv run saber build excytin
uv run saber build excytin --rebuild        # Force rebuild
uv run saber build excytin --image sandbox  # Build specific image

# Build all domains
uv run saber build

# Start permanent services (databases, caches)
uv run saber start excytin

# Tear down Docker resources
uv run saber teardown excytin
uv run saber teardown          # All SABER projects
uv run saber teardown --yes    # Skip confirmation
```

---

## Scoring

SABER uses atomic, factory-created scorers with a unified `ScoringContext` interface. Each scoring unit — submission or subtask checkpoint — is an independent `@scorer` visible in inspect_ai eval logs.

### Built-in Strategies

| Strategy | Description |
|----------|-------------|
| `static` | Exact/substring match against expected answers |
| `llm_judge` | LLM-as-judge with Jinja2 templates (binary or continuous) |
| `tool_call` | Check if specific tools were called |
| `tool_call_count` | Check minimum tool execution count |
| `static_jaccard` | Jaccard similarity for set-based comparison |
| `none` | Always returns 0.0 (placeholder) |

### Score Aggregation

Controls how submission and subtask scores combine:

| Strategy | Formula | Use Case |
|----------|---------|----------|
| `average` | `(norm_sub + norm_step) / 2` | Equal weight per dimension |
| `weighted_sum` | `(raw_sub + raw_step) / (max_sub + max_step)` | Weight by max possible score |
| `max` | `max(norm_sub, norm_step)` | Credit best dimension |

Override via YAML or CLI:
```bash
uv run inspect eval domains/excytin --model openai/gpt-4.1 \
  -T score_aggregation=weighted_sum
```

### Domain-Specific Strategies

Domains can register custom scoring strategies locally (e.g., CTI Realm's trajectory analysis and F1 Sigma scoring) without modifying the core framework.

---

## Concurrency and Performance

```bash
# Sequential execution (debugging)
uv run inspect eval domains/excytin --model openai/azure/gpt-4.1 --max-samples 1

# Parallel execution
uv run inspect eval domains/excytin --model openai/azure/gpt-4.1 \
  --max-samples 4 --max-connections 20

# Limit total samples
uv run inspect eval domains/excytin --model openai/azure/gpt-4.1 --limit 10
```

| Flag | Default | Purpose |
|------|---------|---------|
| `--max-samples` | 8 | Parallel sample/episode count |
| `--max-connections` | 10 | Concurrent LLM API calls |
| `--limit` | All | Total samples to evaluate |

---

## Viewing Results

```bash
# Launch inspect_ai log viewer
uv run inspect view

# View specific evaluation log
uv run inspect view logs/<timestamp>_<domain>_<id>.eval
```

### Analysis Notebooks

For in-depth comparative analysis across models and agent architectures, use the Jupyter notebooks in `notebooks/`. Pre-run sample eval files are included in `eval_samples/` — no need to run evaluations first.

#### Domain-Specific Analysis (Model Comparison)

| Notebook | Description |
|----------|-------------|
| [`eval_analysis.ipynb`](notebooks/eval_analysis.ipynb) | **Domain-agnostic template** — 14 standard experiments (scores, cost, tokens, sub-tasks, agent trajectory, tool usage, effort segmentation, difficulty agreement). Configure `GROUP_FN` for any domain. Start here for new domains. |
| [`excytin_analysis.ipynb`](notebooks/excytin_analysis.ipynb) | **Excytin** — self-contained, 599 tasks × 5 models. All generic analyses plus per-incident gap heatmap and **SQL query analysis** (classifies query outcomes as success/empty/error/large-result). |
| [`cybench_analysis.ipynb`](notebooks/cybench_analysis.ipynb) | **CyBench** — self-contained, CTF challenges × 5 models. All generic analyses plus per-challenge gap heatmap. Small-sample guards for N=1 scenarios. |
| [`cti_realm_analysis.ipynb`](notebooks/cti_realm_analysis.ipynb) | **CTI Realm** — self-contained, 25 tasks × 5 models. All generic analyses plus **per-checkpoint heatmap** (C0–C4), **KQL query quality analysis**, **CTI tool usage patterns**, and **checkpoint correlation analysis**. |

#### Agent Architecture Comparison

| Notebook | Description |
|----------|-------------|
| [`agent_architecture_analysis.ipynb`](notebooks/agent_architecture_analysis.ipynb) | **Domain-agnostic template** — compares React, GH Copilot, and Claude Code agents using the same 14 experiments. |
| [`excytin_agent_architecture_analysis.ipynb`](notebooks/excytin_agent_architecture_analysis.ipynb) | **Excytin** — agent comparison plus safety refusal analysis and SQL query analysis per agent. |
| [`cybench_agent_architecture_analysis.ipynb`](notebooks/cybench_agent_architecture_analysis.ipynb) | **CyBench** — agent comparison for CTF challenges. |
| [`cti_realm_agent_architecture_analysis.ipynb`](notebooks/cti_realm_agent_architecture_analysis.ipynb) | **CTI Realm** — agent comparison for threat intelligence tasks. |

#### Cross-Domain Aggregate Analysis

| Notebook | Description |
|----------|-------------|
| [`aggregate_model_analysis.ipynb`](notebooks/aggregate_model_analysis.ipynb) | **Model comparison across all domains** — domain-normalized scoring (equal weight per domain), ranking consistency, cross-domain radar charts, reasoning impact analysis. |
| [`aggregate_agent_architecture_analysis.ipynb`](notebooks/aggregate_agent_architecture_analysis.ipynb) | **Agent comparison across all domains** — domain-normalized agent ranking, consistency analysis, efficiency comparison. |

#### Sample Eval Data

The `eval_samples/` directory contains pre-run `.eval` files for immediate analysis — no evaluations needed:

- **Models**: Claude Haiku 4.5, Sonnet 4.6, Opus 4.6, GPT-5.4, GPT-5.4-mini
- **Agent architectures**: React, GH Copilot, Claude Code (Sonnet 4.6)
- **Baselines**: No-reasoning/no-thinking variants for extended thinking comparison
- **Auto-download**: Missing files are automatically fetched from [HuggingFace](https://huggingface.co/datasets/anandmudgerikar/AcesEvals) via `ensure_eval_files()`

All notebooks use the shared `notebooks/saber_analysis/` module for data loading and plotting. Generated visualizations are saved to `notebooks/artifacts/`.

To run:
```bash
# Open in VS Code (recommended — use the Jupyter extension)
code notebooks/excytin_analysis.ipynb

# Or launch JupyterLab
uv run jupyter lab notebooks/
```

For the full analysis methodology (14 experiments, interpretation guides, domain-specific analysis details), see the [eval-analysis skill](.github/skills/eval-analysis/SKILL.md).

### Copilot Agent & Skill for Analysis

If you're using GitHub Copilot in VS Code, the repo includes an **analysis agent** and **skill** that make all the notebook analysis knowledge available conversationally:

| File | Purpose |
|------|---------|
| [`.github/agents/analysis.agent.md`](.github/agents/analysis.agent.md) | Analysis agent — routes questions to the right notebook, interprets results, helps run missing evals |
| [`.github/skills/eval-analysis/SKILL.md`](.github/skills/eval-analysis/SKILL.md) | Eval analysis skill — complete methodology reference for all 14+ experiments, domain-specific analyses, and configuration guides |

---

## Development

### Developing Against a Local SABER/ACES Checkout

By default, the `saber` library is installed from the GitHub [ACES](https://github.com/microsoft/ACES) repository. If you need to iterate on the library code locally, switch to an editable local install using the git submodule:

```bash
# 1. Initialize the saber submodule (one-time)
git submodule update --init external/saber

# 2. Make sure your submodule is up to date with the remote
cd external/saber
git fetch origin
git checkout main            # or whichever branch you need
git pull origin main
cd ../..

# 3. Flip pyproject.toml to the local source
#    In [tool.uv.sources], comment the active git line and uncomment the path line:
#
#    [tool.uv.sources]
#    # saber = { git = "...", branch = "main" }
#    saber = { path = "./external/saber", editable = true }

# 4. Re-sync dependencies
uv sync --all-extras
```

To switch **back** to the git-installed version, reverse step 3 (uncomment the git line, comment the path line) and re-run `uv sync --all-extras`.

> **Tip:** Run `git submodule status external/saber` to verify your submodule points at the expected commit. If it shows a `-` prefix, the submodule is not initialized — run `git submodule update --init external/saber`.

### Running Tests

```bash
# Unit tests
uv run pytest external/saber/tests/ -v

# Domain-specific tests
uv run pytest domains/cti_realm/tests/ -v
uv run pytest domains/crsbench/tests/ -v

# With coverage
uv run coverage run -m pytest external/saber/tests/
uv run coverage report
```

### Code Quality

```bash
# Lint and format
uv run ruff check external/saber/src/
uv run ruff format external/saber/src/

# Pre-commit hooks
uv run pre-commit run --all-files
```

### Debugging

```bash
# Verbose logging
INSPECT_LOG_LEVEL=info uv run inspect eval domains/excytin \
  --model openai/azure/gpt-4.1 \
  -T task_filter="incident_5_latest_test_set_task_1"

# Keep sandbox alive after failure (inspect_ai flag)
uv run inspect eval domains/excytin --model openai/azure/gpt-4.1 \
  --no-sandbox-cleanup

# Preflight validation
uv run inspect eval domains/excytin --model openai/azure/gpt-4.1 \
  -T run_preflight=true
```

### Building Custom Domains

1. Create a domain directory under `domains/`:
```
domains/my_domain/
├── my_domain.py               # @task entry point
├── eval.yaml                  # inspect_evals metadata
├── tasks/                     # YAML task definitions
│   ├── global.yaml            # Domain-wide defaults
│   ├── shared/                # Shared config fragments
│   └── *.yaml                 # Individual task files
├── prompts/                   # Jinja2 templates
│   ├── instructions/
│   ├── judge/
│   ├── assistants/
│   ├── submits/
│   └── continues/
├── compose/                   # Docker Compose files
│   └── sandbox.compose.yml
├── docker/                    # Dockerfiles
├── tools/                     # (optional) Domain-specific @tools
└── scoring/                   # (optional) Domain-specific strategies
```

2. Write the `@task` entry point:
```python
from pathlib import Path
from inspect_ai import Task, task
from saber.task import create_task

_domain_root = Path(__file__).resolve().parent

@task
def my_domain(
    task_filter: str | None = None,
    agent: str = "react",
    **kwargs: str | None,
) -> Task:
    return create_task(
        domain_root=_domain_root,
        task_filter=task_filter,
        agent=agent,
        **kwargs,
    )
```

3. Define tasks in YAML with 3-level inheritance (global → shared → task)
4. Create Docker Compose files following inspect_ai conventions

See [docs/design/refactor/05-domain-extensibility.md](docs/design/refactor/05-domain-extensibility.md) for the full domain extension framework.

---

## Documentation

| Document | Purpose |
|----------|---------|
| [Design Docs](docs/design/refactor/README.md) | Full architecture and design documentation |
| [Domain Development](docs/DOMAIN_DEVELOPMENT.md) | Guide for creating new domains |
| [Data Models](docs/design/refactor/01-data-models-and-config.md) | YAML config pipeline and Pydantic models |
| [Scoring Engine](docs/design/refactor/02-scoring-engine.md) | Atomic scorer pipeline |
| [Domain Extensibility](docs/design/refactor/05-domain-extensibility.md) | Custom tools and scoring strategies |
| [Environments](docs/design/refactor/06-environments.md) | Docker Compose conventions |
| [Approval System](docs/design/refactor/09-approval-system.md) | Security validation via inspect_ai Approver |
