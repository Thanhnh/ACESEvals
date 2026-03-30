#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# SABER Eval Monitor — Produces succinct monitoring reports
# ══════════════════════════════════════════════════════════════════════════════
#
# Usage:
#   ./scripts/monitor_evals.sh                    # One-shot report
#   ./scripts/monitor_evals.sh --watch [MINUTES]  # Repeat every N minutes (default: 15)
#   ./scripts/monitor_evals.sh --domain excytin   # Filter to domain
#   ./scripts/monitor_evals.sh --json             # JSON output
#
# The script checks:
#   1. Running inspect eval processes
#   2. Eval file status (complete/error/in-progress)
#   3. Sample counts and progress for in-progress evals
#   4. Docker container health
#   5. Log file tail for errors
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WATCH_INTERVAL=15  # minutes
DOMAIN_FILTER=""
JSON_OUTPUT=false
WATCH_MODE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --watch)
            WATCH_MODE=true
            if [[ "${2:-}" =~ ^[0-9]+$ ]]; then
                WATCH_INTERVAL="$2"; shift
            fi
            shift ;;
        --domain)
            DOMAIN_FILTER="$2"; shift 2 ;;
        --json)
            JSON_OUTPUT=true; shift ;;
        -h|--help)
            head -15 "$0" | tail -10; exit 0 ;;
        *) shift ;;
    esac
done

# ── Colors ──
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

divider() { echo -e "${CYAN}$(printf '═%.0s' {1..72})${NC}"; }

print_report() {
    local timestamp
    timestamp=$(date -u '+%Y-%m-%d %H:%M:%S UTC')

    echo
    divider
    echo -e "${BOLD}  SABER Eval Monitor — ${timestamp}${NC}"
    divider
    echo

    # ── 1. Running Processes ──
    echo -e "${BOLD}▸ Running Eval Processes${NC}"
    local procs
    procs=$(ps aux | grep "inspect eval" | grep -v grep || true)
    if [[ -z "$procs" ]]; then
        echo -e "  ${YELLOW}No eval processes running${NC}"
    else
        local count
        count=$(echo "$procs" | wc -l)
        echo -e "  ${GREEN}${count} eval process(es) active${NC}"
        echo "$procs" | while read -r line; do
            local model agent
            model=$(echo "$line" | grep -oP '(?<=--model )"?[^\s"]+' | tr -d '"' || echo "?")
            agent=$(echo "$line" | grep -oP '(?<=-T agent=)\S+' || echo "react")
            local pid
            pid=$(echo "$line" | awk '{print $2}')
            local cpu
            cpu=$(echo "$line" | awk '{print $3}')
            echo -e "    PID ${pid}  ${BLUE}${model}${NC} × ${agent}  (CPU: ${cpu}%)"
        done
    fi
    echo

    # ── 2. Docker Health ──
    echo -e "${BOLD}▸ Docker Containers${NC}"
    local n_containers
    n_containers=$(docker ps -q 2>/dev/null | wc -l)
    echo -e "  Running: ${n_containers}"
    if (( n_containers > 120 )); then
        echo -e "  ${RED}⚠ High container count — possible resource pressure${NC}"
    fi
    echo

    # ── 3. Eval File Status ──
    echo -e "${BOLD}▸ Eval Files${NC}"
    local domains=("excytin" "cybench" "cti_realm")
    if [[ -n "$DOMAIN_FILTER" ]]; then
        domains=("$DOMAIN_FILTER")
    fi

    for domain in "${domains[@]}"; do
        local dir="$REPO_ROOT/latest_experiments/$domain"
        [[ -d "$dir" ]] || continue

        echo -e "  ${BOLD}${domain}:${NC}"

        # Use Python to extract status, sample counts, and scores from all eval files
        python3 -c "
import zipfile, json, os, sys, statistics

domain_dir = '$dir'
complete = error = started = 0
# Collect named evals
named = []
# Collect timestamp (in-progress) evals to show separately
inflight = []

for fname in sorted(os.listdir(domain_dir)):
    if not fname.endswith('.eval'):
        continue
    fpath = os.path.join(domain_dir, fname)
    size = os.path.getsize(fpath)
    sizeMB = size // 1048576

    is_timestamp = fname[:2] == '20' and fname[4] == '-'

    try:
        with zipfile.ZipFile(fpath) as z:
            names = z.namelist()
            sample_files = [n for n in names if n.startswith('samples/') and n.endswith('.json')]
            n_completed = len(sample_files)

            # Try header.json (complete evals)
            if 'header.json' in names:
                header = json.loads(z.read('header.json'))
                status = header.get('status', '?')
                results = header.get('results', {})
                total_samples = results.get('total_samples', n_completed)
                completed_samples = results.get('completed_samples', n_completed)

                # Extract saber_overall mean score
                score_str = ''
                for sc in results.get('scores', []):
                    if sc.get('name') == 'saber_overall':
                        mean = sc.get('metrics', {}).get('mean', {}).get('value')
                        if mean is not None:
                            score_str = f'score={mean:.3f}'
                        break

                if status == 'success':
                    icon = '\033[0;32m✓\033[0m'
                    detail = f'complete ({completed_samples}/{total_samples} samples, {sizeMB}MB)'
                    if score_str:
                        detail += f'  {score_str}'
                    complete += 1
                else:
                    icon = '\033[0;31m✗\033[0m'
                    detail = f'{status} ({completed_samples}/{total_samples} samples, {sizeMB}MB)'
                    error += 1

                if not is_timestamp:
                    named.append((icon, fname, detail))
                else:
                    named.append((icon, fname, detail))

            elif '_journal/start.json' in names:
                # In-progress eval — extract total from journal
                start_info = json.loads(z.read('_journal/start.json'))
                total_samples = start_info.get('eval', {}).get('dataset', {}).get('samples', '?')

                # Compute running average score from completed samples
                score_str = ''
                if n_completed > 0:
                    scores = []
                    for sf in sample_files:
                        try:
                            sample = json.loads(z.read(sf))
                            sv = sample.get('scores', {}).get('saber_overall', {}).get('value')
                            if sv is not None:
                                scores.append(float(sv))
                        except:
                            pass
                    if scores:
                        avg = statistics.mean(scores)
                        score_str = f'avg_score={avg:.3f}'

                icon = '\033[0;33m⟳\033[0m'
                detail = f'in-progress ({n_completed}/{total_samples} samples, {sizeMB}MB)'
                if score_str:
                    detail += f'  {score_str}'
                started += 1

                if is_timestamp:
                    inflight.append((icon, fname, detail))
                else:
                    named.append((icon, fname, detail))
            else:
                icon = '\033[0;31m✗\033[0m'
                detail = f'error ({sizeMB}MB)'
                error += 1
                if not is_timestamp:
                    named.append((icon, fname, detail))
    except Exception as e:
        if size < 50000:
            icon = '\033[0;31m✗\033[0m'
            detail = f'error ({sizeMB}MB)'
            error += 1
        else:
            icon = '\033[0;33m⟳\033[0m'
            detail = f'in-progress (writing, {sizeMB}MB)'
            started += 1

        if is_timestamp:
            inflight.append((icon, fname, detail))
        else:
            named.append((icon, fname, detail))

total = complete + error + started

for icon, name, detail in named:
    print(f'    {icon} {name:<45s} {detail}')

if inflight:
    print()
    print('    \033[1mIn-flight (unnamed):\033[0m')
    for icon, name, detail in inflight:
        print(f'    {icon} {name:<45s} {detail}')

print(f'    \033[1mSummary: \033[0;32m{complete} complete\033[0m, \033[0;33m{started} in-progress\033[0m, \033[0;31m{error} error\033[0m ({total} total)\033[0m')
" 2>/dev/null
        echo
    done

    # ── 4. Recent Log Activity ──
    echo -e "${BOLD}▸ Recent Log Activity (last 15 min)${NC}"
    local recent_logs
    recent_logs=$(find "$REPO_ROOT/latest_experiments" -name "*_log.txt" -newer <(date -d "15 minutes ago" '+%Y%m%d%H%M') -type f 2>/dev/null | sort || true)
    # Fallback: find logs modified in last 15 min
    recent_logs=$(find "$REPO_ROOT/latest_experiments" -name "*_log.txt" -mmin -15 -type f 2>/dev/null | sort || true)
    if [[ -z "$recent_logs" ]]; then
        echo -e "  ${YELLOW}No recent log activity${NC}"
    else
        echo "$recent_logs" | while read -r logfile; do
            local logname
            logname=$(basename "$logfile")
            local last_line
            last_line=$(tail -1 "$logfile" 2>/dev/null | head -c 120)
            echo -e "  ${logname}: ${last_line}"
        done
    fi
    echo

    # ── 5. Agent Architecture Eval Progress (Excytin) ──
    echo -e "${BOLD}▸ Agent Architecture Evals (Excytin)${NC}"
    python3 -c "
import zipfile, json, os, statistics

edir = '$REPO_ROOT/latest_experiments/excytin'
models = ['sonnet_4.6', 'opus_4.6', 'haiku_4.5', 'gpt_5.4', 'gpt_5.4_mini']
agents = ['react', 'copilot', 'claude_code']
missing = 0
present = 0

# Also find in-flight timestamp evals to map them
inflight_map = {}  # model_agent -> (completed, total, avg_score, file)
for fname in os.listdir(edir):
    if not fname.endswith('.eval') or not fname.startswith('20'):
        continue
    fpath = os.path.join(edir, fname)
    try:
        with zipfile.ZipFile(fpath) as z:
            names = z.namelist()
            if '_journal/start.json' not in names:
                continue
            start = json.loads(z.read('_journal/start.json'))
            eval_info = start.get('eval', {})
            task_args = eval_info.get('task_args', {})
            agent_name = task_args.get('agent', task_args.get('kwargs', {}).get('agent', 'react'))
            model_name = eval_info.get('model', '')
            total = eval_info.get('dataset', {}).get('samples', '?')

            # Map model to short name (check longer names first to avoid prefix match)
            short_model = model_name
            for m in sorted(models, key=len, reverse=True):
                # Normalize both: replace _ with - and . with -
                norm_m = m.replace('_', '-').replace('.', '-')
                norm_model = model_name.replace('.', '-')
                if norm_m in norm_model:
                    short_model = m
                    break

            sample_files = [n for n in names if n.startswith('samples/') and n.endswith('.json')]
            n = len(sample_files)

            # Average score
            scores = []
            for sf in sample_files:
                try:
                    s = json.loads(z.read(sf))
                    v = s.get('scores', {}).get('saber_overall', {}).get('value')
                    if v is not None:
                        scores.append(float(v))
                except:
                    pass
            avg = statistics.mean(scores) if scores else None
            key = f'{short_model}_{agent_name}'
            inflight_map[key] = (n, total, avg, fname)
    except:
        pass

print(f'    {\"Eval\":<40s} {\"Status\":<14s} {\"Samples\":>12s}  {\"Score\":>8s}')
print(f'    {\"─\"*40} {\"─\"*14} {\"─\"*12}  {\"─\"*8}')

for agent in agents:
    for model in models:
        target = f'{model}_{agent}.eval'
        fpath = os.path.join(edir, target)
        key = f'{model}_{agent}'

        if os.path.exists(fpath) and os.path.getsize(fpath) >= 1048576:
            present += 1
            try:
                with zipfile.ZipFile(fpath) as z:
                    header = json.loads(z.read('header.json'))
                    results = header.get('results', {})
                    total = results.get('total_samples', '?')
                    completed = results.get('completed_samples', '?')
                    score = None
                    for sc in results.get('scores', []):
                        if sc.get('name') == 'saber_overall':
                            score = sc.get('metrics', {}).get('mean', {}).get('value')
                            break
                    score_str = f'{score:.3f}' if score is not None else '—'
                    status = header.get('status', '?')
                    icon = '\033[0;32m✓\033[0m' if status == 'success' else '\033[0;31m✗\033[0m'
                    print(f'    {icon} {target:<38s} {\"complete\":<14s} {completed:>5}/{total:<5}  {score_str:>8s}')
            except:
                print(f'    \033[0;31m✗\033[0m {target:<38s} {\"read-error\":<14s}')
        elif key in inflight_map:
            n, total, avg, fname = inflight_map[key]
            pct = f'{n*100//total}%' if isinstance(total, int) and total > 0 else '?'
            avg_str = f'{avg:.3f}' if avg is not None else '—'
            print(f'    \033[0;33m⟳\033[0m {target:<38s} {\"running \"+pct:<14s} {n:>5}/{total:<5}  {avg_str:>8s}')
            missing += 1
        else:
            print(f'    \033[0;31m✗\033[0m {target:<38s} {\"MISSING\":<14s}')
            missing += 1

print()
if missing == 0:
    print(f'  \033[0;32mAll 15 agent architecture evals present!\033[0m')
else:
    print(f'  \033[0;33m{present}/15 complete, {missing} remaining\033[0m')
" 2>/dev/null

    echo
    divider
}

if $WATCH_MODE; then
    echo "Monitoring every ${WATCH_INTERVAL} minutes. Ctrl+C to stop."
    while true; do
        print_report
        sleep $(( WATCH_INTERVAL * 60 ))
    done
else
    print_report
fi
