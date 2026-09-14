#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# SABER-Sim range matrix runner — ranges × agents × harnesses
#
#   ./scripts/run_saber_sim_matrix.sh                       # all ranges, all harnesses
#   ./scripts/run_saber_sim_matrix.sh --harnesses react     # one harness
#   ./scripts/run_saber_sim_matrix.sh --ranges incident_34_v1,incident_5_v1
#   ./scripts/run_saber_sim_matrix.sh --model anthropic/claude-sonnet-4-6
#   ./scripts/run_saber_sim_matrix.sh --epochs 3            # reduce judge noise
#   ./scripts/run_saber_sim_matrix.sh --out-dir latest_experiments/saber_sim_stage2
#   ./scripts/run_saber_sim_matrix.sh --dry-run
#
# Each (range, harness) is ONE inspect invocation covering all six agent tasks,
# so image preflight is paid once instead of per agent.
#
# The queue is ordered by harness on purpose: switching harness flips the sandbox
# base variant (react → saber/sandbox:latest, copilot/claude_code →
# saber/sandbox:agents), and SABER rebuilds the domain sandbox on every flip.
# Grouping by harness costs one rebuild per (harness, range) instead of one per
# agent.
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

MODEL="openai/azure/gpt-5.4"
JUDGE=""                       # defaults to MODEL
HARNESSES="react,copilot,claude_code"
RANGES=""                      # empty = every installed saber_sim_* domain
EPOCHS=3
MAX_SAMPLES=2                  # concurrent sandboxes; each range env is ~11 containers
OUT_DIR=""
DRY_RUN=false
RANGE_DOMAINS_DIR="domains/eval_ranges"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --model)        MODEL="$2"; shift 2 ;;
        --judge)        JUDGE="$2"; shift 2 ;;
        --harnesses)    HARNESSES="$2"; shift 2 ;;
        --ranges)       RANGES="$2"; shift 2 ;;
        --epochs)       EPOCHS="$2"; shift 2 ;;
        --max-samples)  MAX_SAMPLES="$2"; shift 2 ;;
        --out-dir)      OUT_DIR="$2"; shift 2 ;;
        --dry-run)      DRY_RUN=true; shift ;;
        -h|--help)      sed -n '2,18p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done
JUDGE="${JUDGE:-$MODEL}"

OUT_DIR="${OUT_DIR:-$REPO_ROOT/latest_experiments/saber_sim}"
[[ "$OUT_DIR" = /* ]] || OUT_DIR="$REPO_ROOT/$OUT_DIR"
mkdir -p "$OUT_DIR"
BATCH_LOG="$OUT_DIR/matrix_$(date -u '+%Y%m%d_%H%M%S').log"
log() { echo "[$(date -u '+%H:%M:%S')] $*" | tee -a "$BATCH_LOG"; }

INSPECT="$REPO_ROOT/.venv/bin/inspect"
# NOTE: deliberately not `uv run` — that re-syncs from uv.lock and would undo a
# local editable saber checkout mid-run.
[[ -x "$INSPECT" ]] || { echo "missing $INSPECT (run: uv sync --all-extras)" >&2; exit 1; }

# ── Preflight ────────────────────────────────────────────────────────────────
# Both checks below cover failures that are otherwise SILENT: a stale sandbox
# image still runs and still produces scores, it just isn't the image you built.
preflight_fail=0

# Endpoint DNS breaks silently (e.g. Global Secure Access mangling the CNAME
# chain) and costs hours of retries rather than failing fast.
MODEL_HOST=$(grep -hm1 -oE 'AZUREAI_OPENAI_BASE_URL[[:space:]]*=[[:space:]]*"?https://[^"/]+' "$REPO_ROOT/.env" 2>/dev/null | grep -oE '[^/]+$')
check_dns() {
    [[ -z "$MODEL_HOST" ]] && return 0
    "$REPO_ROOT/.venv/bin/python" -c "import socket; socket.getaddrinfo('$MODEL_HOST', 443)" 2>/dev/null
}

# Docker Desktop's WSL integration drops out across restarts, and its shim exits
# non-zero while still printing to stdout — so trust the exit code, not output.
check_docker() {
    docker info >/dev/null 2>&1
}

check_model() {
    "$REPO_ROOT/.venv/bin/python" - "$MODEL" <<'PY' >/dev/null 2>&1
import asyncio
import sys
from pathlib import Path

from dotenv import load_dotenv
from inspect_ai.model import ChatMessageUser, GenerateConfig, get_model


async def main() -> None:
    load_dotenv(Path.cwd() / ".env")
    model = get_model(sys.argv[1])
    await model.api.generate(
        input=[ChatMessageUser(content="ping")],
        tools=[],
        tool_choice="none",
        config=GenerateConfig(max_tokens=1),
    )


asyncio.run(main())
PY
}

validate_eval() {
    local path="$1" expected="$2"
    "$REPO_ROOT/.venv/bin/python" - "$path" "$expected" <<'PY'
import sys

from inspect_ai.log import read_eval_log

path, expected = sys.argv[1], int(sys.argv[2])
try:
    log = read_eval_log(path)
except Exception as exc:
    print(f"unreadable eval: {exc}", file=sys.stderr)
    raise SystemExit(1)

samples = log.samples or []
errors = [str(sample.id) for sample in samples if sample.error]
missing_usage = []
missing_scores = []
for sample in samples:
    output_tokens = sum(
        (usage.output_tokens or 0) for usage in (sample.model_usage or {}).values()
    )
    assistant_messages = sum(
        getattr(message, "role", None) == "assistant" for message in (sample.messages or [])
    )
    if output_tokens == 0 or assistant_messages == 0:
        missing_usage.append(str(sample.id))
    score = (sample.scores or {}).get("saber_overall")
    if score is None or not isinstance(score.value, (int, float)):
        missing_scores.append(str(sample.id))

problems = []
if log.status != "success":
    problems.append(f"status={log.status}")
if len(samples) != expected:
    problems.append(f"samples={len(samples)}/{expected}")
if errors:
    problems.append(f"sample_errors={len(errors)}")
if missing_usage:
    problems.append(f"missing_model_output={len(missing_usage)}")
if missing_scores:
    problems.append(f"missing_scores={len(missing_scores)}")
if problems:
    print(", ".join(problems), file=sys.stderr)
    raise SystemExit(1)
PY
}

if ! check_docker; then
    log "FATAL: docker is not usable (Docker Desktop WSL integration off?)."
    log "       every sandbox build would fail; enable it and re-run to resume."
    preflight_fail=1
fi

if ! check_dns; then
    log "FATAL: cannot resolve model endpoint $MODEL_HOST"
    log "       every model call would fail; check VPN / Global Secure Access DNS."
    preflight_fail=1
fi

if (( ! preflight_fail )) && ! check_model; then
    log "FATAL: model preflight failed for $MODEL"
    log "       no eval cells were started; verify endpoint, credentials, and deployment."
    preflight_fail=1
fi

if ! "$REPO_ROOT/.venv/bin/python" -c "from saber.environments.images import AGENTS_IMAGE_TAG" 2>/dev/null; then
    log "FATAL: installed saber has no base-variant support (AGENTS_IMAGE_TAG missing)."
    log "       copilot/claude_code would silently run on the react-only sandbox."
    preflight_fail=1
fi

for d in "$RANGE_DOMAINS_DIR"/saber_sim_*/; do
    [[ -d "$d" ]] || continue
    "$REPO_ROOT/.venv/bin/python" - "$d" <<'PY' || preflight_fail=1
import sys, yaml, pathlib
d = pathlib.Path(sys.argv[1])
ev = yaml.safe_load((d / "eval.yaml").read_text())
built = ev["images"]["sandbox"]["tag"]
comp = yaml.safe_load((d / "compose" / "sandbox.compose.yaml").read_text())
run = comp["services"]["default"].get("image")
if built != run:
    print(f"FATAL: {d.name}: eval.yaml builds {built} but compose runs {run}")
    sys.exit(1)
PY
done

(( preflight_fail )) && { log "preflight failed — aborting"; exit 1; }

if [[ -z "$RANGES" ]]; then
    RANGES=$(find "$RANGE_DOMAINS_DIR" -mindepth 1 -maxdepth 1 -type d -name 'saber_sim_*' \
        -printf '%f\n' | sed 's/^saber_sim_//' | sort | paste -sd, -)
fi
IFS=',' read -ra RANGE_ARR <<< "$RANGES"
IFS=',' read -ra HARNESS_ARR <<< "$HARNESSES"

log "══════════════════════════════════════════════════════════"
log "SABER-Sim matrix"
log "  model/judge : $MODEL / $JUDGE"
log "  harnesses   : ${HARNESS_ARR[*]}"
log "  ranges      : ${#RANGE_ARR[@]}"
log "  epochs      : $EPOCHS   max-samples: $MAX_SAMPLES"
log "  cells       : $(( ${#RANGE_ARR[@]} * ${#HARNESS_ARR[@]} )) invocations, 6 agents each"
log "══════════════════════════════════════════════════════════"

run_cell() {
    local range="$1" harness="$2"
    local domain="$RANGE_DOMAINS_DIR/saber_sim_${range}"
    local target="$OUT_DIR/${range}_${harness}.eval"
    local task_count expected_samples
    task_count=$(find "$domain/tasks" -maxdepth 1 -name "${range}_*.yaml" -type f | wc -l)
    expected_samples=$(( task_count * EPOCHS ))

    # Size gate only rejects truncated/empty logs; completion is decided by status
    # below. A 3-epoch react log is ~800KB, so anything larger here skips real work.
    if [[ -f "$target" ]] && (( $(stat -c%s "$target") > 10240 )); then
        if validate_eval "$target" "$expected_samples"; then
            log "SKIP  ${range}/${harness} (already complete)"
            return 0
        fi
        log "REDO  ${range}/${harness} (existing archive failed completeness checks)"
        mv "$target" "${target}.invalid.$(date -u '+%Y%m%d_%H%M%S')"
    fi

    local filter
    filter=$(ls "$domain"/tasks/*.yaml | xargs -n1 basename | sed 's/\.yaml$//' | grep -v '^global$' | paste -sd, -)

    if $DRY_RUN; then
        log "WOULD RUN ${range}/${harness}  (${filter//,/ })"
        return 0
    fi

    if ! check_docker; then
        log "ABORT ${range}/${harness}: docker unusable — stopping rather than burning"
        log "      cells on failed image builds. Fix Docker and re-run to resume."
        exit 1
    fi

    if ! check_dns; then
        log "ABORT ${range}/${harness}: cannot resolve $MODEL_HOST — stopping rather than"
        log "      recording DNS failures as scores. Fix DNS and re-run to resume."
        exit 1
    fi

    if ! check_model; then
        log "ABORT ${range}/${harness}: model preflight failed for $MODEL"
        log "      no sample was started; fix provider connectivity and re-run to resume."
        exit 1
    fi

    log "START ${range}/${harness}"
    local before after new
    before=$(ls "$OUT_DIR"/*.eval 2>/dev/null | sort || true)
    if INSPECT_LOG_DIR="$OUT_DIR" "$INSPECT" eval "$domain" \
            -T task_filter="$filter" \
            -T agent="$harness" \
            -T judge_llm="$JUDGE" \
            --model "$MODEL" \
            --epochs "$EPOCHS" \
            --max-samples "$MAX_SAMPLES" \
            --no-fail-on-error \
            --display plain \
            >> "$OUT_DIR/${range}_${harness}.log" 2>&1; then
        after=$(ls "$OUT_DIR"/*.eval 2>/dev/null | sort || true)
        new=$(comm -13 <(echo "$before") <(echo "$after") | head -1)
        [[ -n "$new" && -f "$new" ]] && mv "$new" "$target"
        # Inspect can report success after salvaging a bridge session with no
        # model output, so validate every sample rather than trusting status.
        if validate_eval "$target" "$expected_samples"; then
            log "DONE  ${range}/${harness}"
        else
            log "FAIL  ${range}/${harness} (archive failed completeness checks)"
            mv "$target" "${target}.invalid" 2>/dev/null || true
            return 1
        fi
    else
        log "FAIL  ${range}/${harness} (see ${range}_${harness}.log)"
        return 1
    fi
}

# Harness outer, range inner — see the base-variant note at the top.
for harness in "${HARNESS_ARR[@]}"; do
    for range in "${RANGE_ARR[@]}"; do
        run_cell "$range" "$harness"
    done
done

log "matrix complete — results in $OUT_DIR"
