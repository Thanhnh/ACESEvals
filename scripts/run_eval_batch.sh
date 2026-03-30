#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# SABER Eval Batch Runner — Runs evals with concurrency control
# ══════════════════════════════════════════════════════════════════════════════
#
# Usage:
#   ./scripts/run_eval_batch.sh                        # Run all missing evals
#   ./scripts/run_eval_batch.sh --max-concurrent 2     # Override concurrency
#   ./scripts/run_eval_batch.sh --domain excytin       # Specific domain
#   ./scripts/run_eval_batch.sh --dry-run              # Show what would run
#
# Features:
#   - Runs up to N evals concurrently (default: 3)
#   - Skips already-completed evals (>1MB file = complete)
#   - Auto-renames eval output files to standard names
#   - Copies completed evals to eval_samples/
#   - Logs per-eval and batch-level output
#   - Monitors and reports progress
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MAX_CONCURRENT=3
DOMAIN="excytin"
DRY_RUN=false
MAX_SAMPLES=64
MAX_CONNECTIONS=20

while [[ $# -gt 0 ]]; do
    case "$1" in
        --max-concurrent) MAX_CONCURRENT="$2"; shift 2 ;;
        --domain) DOMAIN="$2"; shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        --max-samples) MAX_SAMPLES="$2"; shift 2 ;;
        --max-connections) MAX_CONNECTIONS="$2"; shift 2 ;;
        -h|--help) head -18 "$0" | tail -14; exit 0 ;;
        *) shift ;;
    esac
done

OUT_DIR="$REPO_ROOT/latest_experiments/$DOMAIN"
EVAL_SAMPLES_DIR="$REPO_ROOT/eval_samples/$DOMAIN"
BATCH_LOG="$OUT_DIR/eval_batch_$(date -u '+%Y%m%d_%H%M%S').log"
mkdir -p "$OUT_DIR" "$EVAL_SAMPLES_DIR"

# Load API keys from .env
if [[ -f "$REPO_ROOT/.env" ]]; then
    export ANTHROPIC_API_KEY="$(grep '^ANTHROPIC_API_KEY' "$REPO_ROOT/.env" | head -1 | sed 's/.*= *//' | tr -d '"')"
    export AZUREAI_OPENAI_BASE_URL="$(grep '^AZUREAI_OPENAI_BASE_URL' "$REPO_ROOT/.env" | head -1 | sed 's/.*= *//' | tr -d '"')"
    export AZUREAI_OPENAI_API_VERSION="$(grep '^AZUREAI_OPENAI_API_VERSION' "$REPO_ROOT/.env" | head -1 | sed 's/.*= *//' | tr -d '"')"
fi

log() { echo "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] $*" | tee -a "$BATCH_LOG"; }

# ══════════════════════════════════════════════════════════════════════════════
# EVAL REGISTRY — Define all evals to run
# Each entry: short_name|model_id|agent|api_version_override(optional)
# ══════════════════════════════════════════════════════════════════════════════
declare -a EVAL_QUEUE=()

if [[ "$DOMAIN" == "excytin" ]]; then
    # Agent architecture matrix: 5 models × 3 agents = 15 evals
    MODELS=(
        "sonnet_4.6|anthropic/claude-sonnet-4-6"
        "opus_4.6|anthropic/claude-opus-4-6"
        "haiku_4.5|anthropic/claude-haiku-4-5"
        "gpt_5.4|openai/azure/gpt-5.4"
        "gpt_5.4_mini|openai/azure/gpt-5.4-mini|2024-12-01-preview"
    )
    AGENTS=("react" "copilot" "claude_code")

    for agent in "${AGENTS[@]}"; do
        for model_entry in "${MODELS[@]}"; do
            IFS='|' read -r short_name model_id api_ver <<< "$model_entry"
            EVAL_QUEUE+=("${short_name}|${model_id}|${agent}|${api_ver:-}")
        done
    done
fi

# ══════════════════════════════════════════════════════════════════════════════
# FILTER — Skip completed evals
# ══════════════════════════════════════════════════════════════════════════════
declare -a PENDING_EVALS=()
for entry in "${EVAL_QUEUE[@]}"; do
    IFS='|' read -r short_name model_id agent api_ver <<< "$entry"
    target="${short_name}_${agent}.eval"
    target_path="$OUT_DIR/$target"

    if [[ -f "$target_path" ]]; then
        size=$(stat -c%s "$target_path" 2>/dev/null || echo 0)
        if (( size > 1048576 )); then
            # Check if it's actually complete (success status)
            status=$(python3 -c "
import zipfile, json
try:
    with zipfile.ZipFile('$target_path') as z:
        h = json.loads(z.read('header.json'))
        print(h.get('status', 'unknown'))
except: print('error')
" 2>/dev/null || echo "error")
            if [[ "$status" == "success" ]]; then
                log "SKIP $target (complete, ${size} bytes)"
                continue
            fi
        fi
        # Small or errored — remove and retry
        if $DRY_RUN; then
            log "WOULD REMOVE stale $target (${size} bytes)"
        else
            log "REMOVING stale $target (${size} bytes, will retry)"
            rm -f "$target_path" "$EVAL_SAMPLES_DIR/$target"
        fi
    fi

    PENDING_EVALS+=("$entry")
done

log "══════════════════════════════════════════════════════════════"
log "SABER Eval Batch Runner"
log "  Domain:       $DOMAIN"
log "  Concurrency:  $MAX_CONCURRENT"
log "  Total evals:  ${#EVAL_QUEUE[@]}"
log "  Pending:      ${#PENDING_EVALS[@]}"
log "  Max samples:  $MAX_SAMPLES"
log "  Batch log:    $BATCH_LOG"
log "══════════════════════════════════════════════════════════════"

if $DRY_RUN; then
    log "DRY RUN — would launch these evals:"
    for entry in "${PENDING_EVALS[@]}"; do
        IFS='|' read -r short_name model_id agent api_ver <<< "$entry"
        log "  ${short_name}_${agent}.eval  ($model_id × $agent)"
    done
    exit 0
fi

if (( ${#PENDING_EVALS[@]} == 0 )); then
    log "All evals complete! Nothing to do."
    exit 0
fi

# ══════════════════════════════════════════════════════════════════════════════
# RUNNER — Launch evals with concurrency control
# ══════════════════════════════════════════════════════════════════════════════
declare -a ACTIVE_PIDS=()
declare -a ACTIVE_NAMES=()
completed=0
failed=0
total_pending=${#PENDING_EVALS[@]}

run_single_eval() {
    local short_name="$1" model_id="$2" agent="$3" api_ver="$4"
    local target="${short_name}_${agent}.eval"
    local eval_log="$OUT_DIR/${short_name}_${agent}_log.txt"

    echo "[$(date -u)] START $target ($model_id × $agent)" > "$eval_log"
    local before_files
    before_files=$(ls "$OUT_DIR"/*.eval 2>/dev/null | sort || true)

    local env_prefix=""
    if [[ -n "$api_ver" ]]; then
        env_prefix="AZUREAI_OPENAI_API_VERSION=$api_ver"
    fi

    if env $env_prefix INSPECT_LOG_DIR="$OUT_DIR" uv run inspect eval "domains/$DOMAIN" \
        --model "$model_id" \
        --display plain \
        --max-samples "$MAX_SAMPLES" \
        --max-connections "$MAX_CONNECTIONS" \
        -T agent="$agent" \
        -T keep_permanent=true \
        -T dataset=latest_test_set \
        >> "$eval_log" 2>&1; then

        local after_files
        after_files=$(ls "$OUT_DIR"/*.eval 2>/dev/null | sort || true)
        local new_file
        new_file=$(comm -13 <(echo "$before_files") <(echo "$after_files") | head -1)
        if [[ -n "$new_file" && -f "$new_file" ]]; then
            mv "$new_file" "$OUT_DIR/$target"
            cp "$OUT_DIR/$target" "$EVAL_SAMPLES_DIR/$target"
            echo "[$(date -u)] DONE $target" >> "$eval_log"
            return 0
        fi
    fi

    echo "[$(date -u)] FAIL $target" >> "$eval_log"
    local after_files
    after_files=$(ls "$OUT_DIR"/*.eval 2>/dev/null | sort || true)
    local new_file
    new_file=$(comm -13 <(echo "$before_files") <(echo "$after_files") | head -1)
    if [[ -n "$new_file" && -f "$new_file" ]]; then
        mv "$new_file" "$OUT_DIR/$target"
        echo "[$(date -u)] Saved partial as $target" >> "$eval_log"
    fi
    return 1
}

reap_finished() {
    local new_pids=() new_names=()
    for i in "${!ACTIVE_PIDS[@]}"; do
        local pid="${ACTIVE_PIDS[$i]}"
        local name="${ACTIVE_NAMES[$i]}"
        if kill -0 "$pid" 2>/dev/null; then
            new_pids+=("$pid")
            new_names+=("$name")
        else
            wait "$pid" 2>/dev/null
            local ec=$?
            if (( ec == 0 )); then
                log "DONE  $name"
                completed=$((completed + 1))
            else
                log "FAIL  $name (exit=$ec)"
                failed=$((failed + 1))
            fi
        fi
    done
    ACTIVE_PIDS=("${new_pids[@]+"${new_pids[@]}"}")
    ACTIVE_NAMES=("${new_names[@]+"${new_names[@]}"}")
}

# Launch evals with concurrency control
for entry in "${PENDING_EVALS[@]}"; do
    IFS='|' read -r short_name model_id agent api_ver <<< "$entry"
    local_target="${short_name}_${agent}.eval"

    # Wait for a free slot
    while true; do
        reap_finished
        if (( ${#ACTIVE_PIDS[@]} < MAX_CONCURRENT )); then
            break
        fi
        sleep 10
    done

    log "START $local_target ($model_id × $agent)  [$(( completed + failed + ${#ACTIVE_PIDS[@]} + 1 ))/$total_pending]"
    run_single_eval "$short_name" "$model_id" "$agent" "$api_ver" &
    ACTIVE_PIDS+=("$!")
    ACTIVE_NAMES+=("$local_target")

    sleep 5
done

# Wait for all remaining
log "Waiting for ${#ACTIVE_PIDS[@]} remaining eval(s)..."
while (( ${#ACTIVE_PIDS[@]} > 0 )); do
    reap_finished
    if (( ${#ACTIVE_PIDS[@]} > 0 )); then
        sleep 10
    fi
done

log "══════════════════════════════════════════════════════════════"
log "Batch complete: $completed succeeded, $failed failed out of $total_pending"
log "══════════════════════════════════════════════════════════════"
