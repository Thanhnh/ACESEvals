---
name: eval-monitoring
description: >
  Guide for monitoring running SABER evaluations, checking progress, and managing eval batches.
  Use this when asked to monitor evals, check progress, produce a status report, or manage
  concurrent eval runs. Also covers Docker health and resource management.
---

# Eval Monitoring Skill

## Quick Status Check

Run the monitoring script for an instant report:

```bash
./scripts/monitor_evals.sh
```

For continuous monitoring (every 15 minutes):
```bash
./scripts/monitor_evals.sh --watch 15
```

## Manual Monitoring Commands

### 1. Check Running Processes

```bash
# Count running evals
ps aux | grep "inspect eval" | grep -v grep | wc -l

# See model and agent for each
ps aux | grep "inspect eval" | grep -v grep | \
  grep -oP '(?<=--model )"?[^\s"]+' | tr -d '"'
```

### 2. Check Eval File Progress

> **Staleness note:** `.eval` ZIP files are flushed in batches by inspect_ai, so sample
> counts read from them lag **2–3 minutes** behind the live results visible in the
> `inspect view` UI. This is expected — treat `.eval` reads as "near-real-time" rather
> than exact.

```python
# Quick sample count for an in-progress eval
python3 -c "
import zipfile, json
with zipfile.ZipFile('path/to/file.eval') as z:
    samples = [n for n in z.namelist() if n.startswith('samples/') and n.endswith('.json')]
    header = json.loads(z.read('header.json'))
    print(f'Status: {header.get(\"status\")}, Samples: {len(samples)}')
"
```

### 3. Check Docker Health

```bash
# Container count (>120 = resource pressure)
docker ps -q | wc -l

# Check for stuck containers
docker ps --format '{{.Names}} {{.Status}}' | grep -i "unhealthy\|restarting"
```

### 4. Check Log Files for Errors

```bash
# Find recently active logs
find latest_experiments/ -name "*_log.txt" -mmin -15 -exec tail -3 {} +

# Check a specific eval log
tail -20 latest_experiments/excytin/sonnet_4.6_claude_code_log.txt
```

## Batch Running

### Launch All Missing Evals (3 concurrent)

```bash
./scripts/run_eval_batch.sh --domain excytin --max-concurrent 3
```

### Dry Run (see what would be launched)

```bash
./scripts/run_eval_batch.sh --domain excytin --dry-run
```

### Override Concurrency

```bash
# Conservative: 2 at a time
./scripts/run_eval_batch.sh --max-concurrent 2

# Only if Docker resources allow: 4 at a time
./scripts/run_eval_batch.sh --max-concurrent 4
```

## Concurrency Guidelines

| Concurrent Evals | Docker Resources | When to Use |
|-------------------|------------------|-------------|
| 1 | Minimal (~20 containers) | Debugging, resource-constrained |
| 2-3 | Moderate (~60-100) | **Recommended default** |
| 4-5 | Heavy (~100-160) | Only with fast models + good hardware |
| 6+ | Excessive (160+) | **AVOID** — Docker compose timeouts |

**Key rule: Never run more than 3 concurrent evals with `--max-samples 64`.** Each eval
can spawn up to 16 Docker sandbox containers simultaneously, plus the permanent services.

## Eval File Naming Convention

Eval files follow this pattern: `{model_slug}_{agent}.eval`

| Model Slug | Model ID |
|------------|----------|
| `sonnet_4.6` | `anthropic/claude-sonnet-4-6` |
| `opus_4.6` | `anthropic/claude-opus-4-6` |
| `haiku_4.5` | `anthropic/claude-haiku-4-5` |
| `gpt_5.4` | `openai/azure/gpt-5.4` |
| `gpt_5.4_mini` | `openai/azure/gpt-5.4-mini` |

| Agent | Description |
|-------|-------------|
| `react` | Default React agent (step-by-step reasoning) |
| `copilot` | GH Copilot agent |
| `claude_code` | Claude Code agent |

## Interpreting Eval File Status

| File Size | Status | Action |
|-----------|--------|--------|
| <50KB | Error/empty | Delete and retry |
| 50KB-1MB | Partial (few samples) | Delete and retry |
| >1MB | Likely has data | Check `header.json` status field |
| Status: `success` | Complete | Skip |
| Status: `error` | Failed mid-run | Check error, may need retry |
| Status: `started` | In progress or abandoned | Check if process alive |

## Common Failure Modes

### Docker Compose Timeout
**Symptom:** `TimeoutError: Docker compose command ... timed out after 45 seconds`
**Cause:** Too many concurrent evals or Docker resource exhaustion
**Fix:** Kill all evals, `docker container prune -f`, relaunch with lower concurrency

### DeploymentNotFound (Azure)
**Symptom:** `DeploymentNotFound` in pre-flight check
**Cause:** Wrong deployment name or API version
**Fix:** Check deployment name matches Azure portal. Use `AZUREAI_OPENAI_API_VERSION` override.

### Safety Refusals (0% scores)
**Symptom:** All scores 0.0, answers contain "I cannot", "social engineering"
**Cause:** Model safety guardrails triggered by benchmark prompts
**Fix:** Document in `model_safety_filters_analysis.ipynb`, not a retry-able error

## Docker Reset Procedure

When Docker is in a bad state:

```bash
# 1. Gracefully stop all eval processes (allow cleanup of .eval files and Docker resources)
pkill -f "inspect eval"
sleep 10  # Give processes time to flush and clean up

# 2. Force-kill only if any are still running
pkill -9 -f "inspect eval" 2>/dev/null

# 3. Stop all containers (xargs -r skips if no containers are running)
docker ps -q | xargs -r docker stop

# 4. Remove stopped containers
docker container prune -f

# 5. Verify clean state
docker ps -q | wc -l  # Should be 0

# 6. Relaunch evals
./scripts/run_eval_batch.sh --domain excytin --max-concurrent 3
```
