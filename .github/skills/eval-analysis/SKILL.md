---
name: eval-analysis
description: >
  Comprehensive guide for analyzing SABER evaluation results — model comparison, agent architecture
  comparison, domain-specific analysis, and cross-domain aggregate analysis. Use this when asked to
  analyze eval results, compare models, generate visualizations, interpret scores, investigate
  cost-efficiency trade-offs, or extend analysis to new domains.
---

# Eval Analysis Skill

## Overview

SABER evaluation analysis is a structured data science framework for comparing AI agent performance across cybersecurity benchmark domains. The analysis pipeline transforms `.eval` log files into actionable insights through 12+ standardized experiments plus domain-specific analyses.

## Getting Started: Sample Eval Data

**No evals to analyze yet?** The repo ships with pre-run sample `.eval` files and can auto-download more from HuggingFace.

### Option 1: Use bundled sample evals (fastest)

The `eval_samples/` directory contains pre-run evaluation results for all 3 domains across 5 models and 3 agent architectures:

```
eval_samples/
├── excytin/          # 20 eval files (5 models × default + reasoning baselines + 3 agents)
├── cybench/          # 17 eval files
└── cti_realm/        # 11 eval files
```

**Models included**: Claude Haiku 4.5, Claude Sonnet 4.6, Claude Opus 4.6, GPT-5.4, GPT-5.4-mini  
**Agent architectures included**: React, GH Copilot, Claude Code (for Sonnet 4.6)  
**Baselines**: No-reasoning/no-thinking variants for extended thinking comparison

The notebooks are pre-configured to load from `eval_samples/`. Just run any notebook — no configuration needed.

### Option 2: Auto-download from HuggingFace

If `.eval` files are missing locally, `ensure_eval_files()` automatically downloads them from the **[AcesEvals HuggingFace dataset](https://huggingface.co/datasets/anandmudgerikar/AcesEvals)**:

```python
from saber_analysis import ensure_eval_files

ensure_eval_files(
    eval_logs=EVAL_LOGS,       # {display_name: filename.eval}
    log_dir=LOG_DIR,           # local directory
    domain='excytin',          # HuggingFace subfolder
    fallback_dirs=[            # check these before downloading
        str(REPO_ROOT / 'eval_samples' / 'excytin'),
        str(REPO_ROOT / 'latest_experiments' / 'excytin'),
    ],
)
```

**Resolution order**: local `log_dir` → `fallback_dirs` → HuggingFace download  
**HuggingFace repo**: `anandmudgerikar/AcesEvals` (dataset type)  
**HuggingFace path**: `latest_experiment_samples/{domain}/{filename}.eval`

### Option 3: Run your own evaluations

If you need results for a model or agent architecture not in the sample evals:

```bash
# Run for a new model
uv run inspect eval domains/<domain> --model <api/model-id> --display plain

# Run for a specific agent architecture
uv run inspect eval domains/<domain> --model <api/model-id> -T agent=react --display plain
uv run inspect eval domains/<domain> --model <api/model-id> -T agent=copilot --display plain

# Run with extended reasoning disabled (for baseline comparison)
# Set INSPECT_EVAL_MODEL_ARGS=reasoning_effort=none or configure in .env
```

Then copy the `.eval` file to `eval_samples/<domain>/` or `latest_experiments/<domain>/` and add it to the notebook's `EVAL_LOGS` configuration.

### What's available vs. what you need to run

| Domain | Models (sample evals) | Agent Architectures (sample evals) | What to run yourself |
|--------|-----------------------|-------------------------------------|----------------------|
| Excytin | Haiku 4.5, Sonnet 4.6, Opus 4.6, GPT-5.4, GPT-5.4-mini | React, Copilot, Claude Code (Sonnet) | New models, new agents on non-Sonnet models |
| CyBench | Haiku 4.5, Sonnet 4.6, Opus 4.6, GPT-5.4, GPT-5.4-mini | React, Copilot, Claude Code (Sonnet) | New models, new agents, more challenges |
| CTI Realm | Haiku 4.5, Sonnet 4.6, Opus 4.6, GPT-5.4, GPT-5.4-mini | Copilot, Claude Code (Sonnet) | React for non-Sonnet models, new models |

### Notebook Inventory

| Notebook | Scope | When to use |
|----------|-------|-------------|
| `notebooks/eval_analysis.ipynb` | Domain-agnostic template | Analyzing any single domain's model results; starting point for new domains |
| `notebooks/excytin_analysis.ipynb` | Excytin-specific (self-contained) | Full analysis of Excytin incident response domain |
| `notebooks/cybench_analysis.ipynb` | CyBench-specific (self-contained) | Full analysis of CyBench CTF challenges |
| `notebooks/cti_realm_analysis.ipynb` | CTI Realm-specific (self-contained) | Full analysis of CTI Realm threat intel domain |
| `notebooks/agent_architecture_analysis.ipynb` | Agent comparison template | Comparing agent architectures (React, Copilot, Claude Code) on any domain |
| `notebooks/excytin_agent_architecture_analysis.ipynb` | Excytin agent comparison | Agent architecture analysis specific to Excytin |
| `notebooks/cybench_agent_architecture_analysis.ipynb` | CyBench agent comparison | Agent architecture analysis specific to CyBench |
| `notebooks/cti_realm_agent_architecture_analysis.ipynb` | CTI Realm agent comparison | Agent architecture analysis specific to CTI Realm |
| `notebooks/aggregate_model_analysis.ipynb` | Cross-domain model comparison | Aggregate model analysis across all domains (normalized) |
| `notebooks/aggregate_agent_architecture_analysis.ipynb` | Cross-domain agent comparison | Aggregate agent architecture analysis across all domains |
| `notebooks/model_safety_filters_analysis.ipynb` | Safety filter investigation | Analyzing model safety refusals and guardrail triggers |
| `notebooks/excytin_basic_analysis.ipynb` | Quick Excytin analysis | Lightweight Excytin analysis for rapid iteration |

### Shared Analysis Library

The `notebooks/saber_analysis/` package provides reusable utilities:

| Module | Functions | Purpose |
|--------|-----------|---------|
| `data_loader.py` | `ensure_eval_files()`, `load_eval_logs()`, `load_baseline_logs()`, `load_trajectory_data()` | Standardized .eval parsing; HuggingFace fallback downloads; typed inspect_ai log API |
| `cost.py` | `calc_cost()`, `extract_cost_rows()` | Token→dollar conversion using per-model pricing |
| `plots.py` | `setup_plotting()`, `make_legend_patches()`, `classify_score_type()` | Consistent matplotlib styling across all notebooks |

---

## Data Pipeline

```
.eval ZIP archives
    │
    ├── header.json          → run metadata, overall saber_overall scores
    ├── samples/*.json       → per-sample messages, scores, timing, tool calls
    └── summaries.json       → aggregated score summaries
    │
    ▼
inspect_ai.log API
    ├── read_eval_log(path, header_only=True)       → EvalLog with results.scores
    ├── read_eval_log_sample_summaries(path)         → per-sample scores & timing
    └── read_eval_log_sample(path, id=...)           → full messages & tool calls
    │
    ▼
saber_analysis library
    ├── ensure_eval_files()  → locates locally or downloads from HuggingFace
    ├── load_eval_logs()     → parses into DataFrames (overall_df, samples_df, subtasks_df)
    ├── load_trajectory_data() → extracts tool calls, steps, timing per sample
    └── extract_cost_rows()  → builds cost DataFrame from token usage + pricing
    │
    ▼
Notebook Configuration
    ├── EVAL_LOGS: dict[str, str]      → {display_name: filename.eval}
    ├── COLORS: dict[str, str]         → {display_name: hex_color}
    ├── PRICING: dict[str, dict]       → {api_model_id: {input, output, cache_read, cache_write}}
    ├── GROUP_FN: Callable             → domain-specific sample ID → group label
    └── NO_THINKING_LOGS (optional)    → baseline without extended reasoning
    │
    ▼
Analysis Cells (Experiments 1–14+)
    │
    ▼
Artifacts saved to notebooks/artifacts/{domain}/*.png
```

### Key DataFrames

| DataFrame | Columns | Source |
|-----------|---------|--------|
| `overall_df` | model, mean, stderr | `load_eval_logs()` — header-level saber_overall |
| `samples_df` | model, sample_id, group, score | `load_eval_logs()` — per-sample saber_overall |
| `subtasks_df` | model, sample_id, group, score_type, score | `load_eval_logs()` — submission/checkpoint/aggregate breakdown |
| `traj_df` | model, sample_id, n_tool_calls, n_steps, total_time, tool_counts | `load_trajectory_data()` — agent behavior data |
| `cost_df` | model, score, input_tokens, output_tokens, cache_read, cache_write, reasoning_tokens, total_cost, cost_per_sample | `extract_cost_rows()` |

---

## Domain-Agnostic Analysis Types (Experiments 1–14)

These 14 core analyses apply to **any** SABER domain. They appear in `eval_analysis.ipynb` and every domain-specific notebook.

### Experiment 1: Overall Reward Distribution

- **Metric**: Mean `saber_overall` score per model
- **Visualization**: Bar chart with error bars (stderr) + optional hatched overlay for reasoning delta
- **Interpretation**:
  - Higher bars = better performance
  - Overlapping error bars = statistically insignificant differences
  - Reasoning delta (hatched) shows impact of extended thinking (positive = reasoning helps)
- **Code pattern**:
  ```python
  overall_df.plot.bar(x='model', y='mean', yerr='stderr')
  ```

### Experiment 2: Per-Group Breakdown (Domain-Specific Grouping)

- **Metric**: Scores segmented by `GROUP_FN` dimension
- **Visualization**: Clustered bar chart (models × groups)
- **Group functions by domain**:
  - **Excytin**: `'_'.join(id.split('_')[:2])` → 8 security incidents
  - **CyBench**: `'_'.join(id.split('_')[:-2])` → challenge types
  - **CTI Realm**: `id.split('_')[0]` → 3 platforms (Linux, AKS, Cloud)
- **Interpretation**:
  - Large within-group variance = model-dependent difficulty
  - Shifting model rankings across groups = no single dominant model
  - Uniform clusters = inherently hard/easy groups
- **Requires**: Setting `GROUP_FN` in configuration; set `GROUP_FN = None` to skip

### Experiment 3: Cost Analysis

- **Metrics**: Total cost ($), cost per sample, token breakdown (input/output/cache/reasoning)
- **Visualizations**:
  1. Total cost bar chart
  2. Cost per sample bar chart
  3. Pareto frontier (Score vs. Cost — upper-left corner = best value)
- **Interpretation**:
  - Pareto-dominant models: no other model is both cheaper AND better
  - Arrows on Pareto chart show reasoning cost delta
  - Diminishing returns visible from frontier plateau
- **Code pattern**:
  ```python
  cost_df = pd.DataFrame(extract_cost_rows(EVAL_LOGS, LOG_DIR, PRICING, N_SAMPLES))
  ```

### Experiment 4: Token Usage Breakdown

- **Metrics**: Input, output, cache read/write, reasoning tokens per model
- **Visualization**: Horizontal stacked bar chart
- **Interpretation**:
  - **Input tokens**: Prompts, tool results, conversation history
  - **Output tokens**: Generated text, tool calls, answers
  - **Cache read/write**: Prompt caching (Claude > GPT generally)
  - **Reasoning tokens**: Extended thinking overhead; highly variable by model family
  - Large hatched sections = reasoning adds substantial overhead

### Experiment 5: Cost Efficiency (Reward per Dollar)

- **Formula**: `Cost Efficiency = Mean SABER Score / Total Cost ($)`
- **Visualization**: Bar chart (taller = more efficient)
- **Interpretation**:
  - Highest-cost model is not always least efficient
  - Budget-constrained deployments should prioritize high-efficiency models
  - Reasoning may increase OR decrease efficiency (depends on score gain vs. cost increase)

### Experiment 6: Sub-Task Score Breakdown

- **Metrics**: Submission score, checkpoint scores, aggregate score per model
- **Visualization**: Grouped bars (submission/checkpoints/aggregate) with reasoning delta overlay
- **Interpretation**:
  - **Submission >> Checkpoints**: Model reaches correct conclusion without thorough investigation (may be guessing; risky in production)
  - **Checkpoints >> Submission**: Model investigates well but fails at synthesis
  - **Aligned**: Investigation matches answer quality (ideal)

### Experiment 7: Checkpoint Score Distributions

- **Visualization**: Violin plots per model
- **Interpretation**:
  - **Bimodal** (peaks at 0 and 1): Binary pass/fail checkpoint; few partial successes
  - **Continuous**: Fine-grained scoring; various intermediate scores
  - **Wide violins**: Inconsistent across samples; **narrow**: consistent
  - **Long upper tails**: Some samples max out the checkpoint score

### Experiment 8: Domain-Specific Gap Analysis

- **Purpose**: Submission vs. checkpoint gap per domain grouping dimension
- **Visualization**: Heatmap (models × groups) showing gap = submission - checkpoint
- **Interpretation**:
  - Red (positive gap): Model guesses correctly without thorough investigation
  - Green (negative gap): Model investigates well but fails at synthesis
  - Yellow (aligned): Investigation matches answer quality

### Experiment 9: Agent Trajectory Analysis

Data loading step that extracts per-sample behavioral data:
- `n_tool_calls`: Actual tool invocations per sample
- `n_steps`: Assistant message turns per sample
- `tool_counts`: Per-tool breakdown (bash, python, domain tools)
- `total_time`: Wall-clock seconds per sample

### Experiment 9a: Score vs. Tool-Call Limit (Effort Budget)

- **Calculation**: For each hypothetical limit N, mean score where samples needing >N calls score 0
- **Visualization**: Curves per model converging to actual mean at real tool-call cap
- **Interpretation**:
  - **Steep early rise**: Efficient model (solves many tasks in first 5–15 calls)
  - **Plateau**: Budget increase yields diminishing returns
  - **Key finding**: All models typically reach 95% of final score by ~20–25 calls (Excytin) or ~33–35 (CTI Realm)

### Experiment 9b: Effort Distribution per Model

- **Visualization**: Violin plots of tool calls and steps per sample per model
- **Interpretation**:
  - **Narrow, low**: Efficient (quick solutions)
  - **Wide, high**: Variable effort or struggling
  - **Long upper tail**: Some samples hit tool-call limit (binding constraint)

### Experiment 10: Tool Usage Analysis

- **Visualization**: Dual panel — left: mean tool calls per tool (absolute); right: tool call ratio (fraction)
- **Interpretation**:
  - Domain determines tool preferences (Excytin → 95%+ bash; CTI Realm → 48% KQL tools)
  - Cross-model consistency = task design funnels agents toward certain tools
  - Model-specific tool preferences reveal different investigation strategies

### Experiment 11: Time Efficiency & Reward per Tool Call

- **Formulas**:
  - `Reward/Call = Mean SABER Score / Mean Tool Calls`
  - `Reward/Minute = Mean Score / Wall-Clock Time (min)`
- **Visualizations**: Bar charts, scatter plots (effort vs. score with trend line), time distribution violin plots
- **Interpretation**:
  - High reward/call = doesn't waste invocations
  - High reward/minute = fast AND accurate
  - Time outliers reveal latency issues (e.g., GPT 10+ min vs. Claude 2–3 min)

### Experiment 12: Score Outcome Segmentation by Effort

- **Methodology**: Segment by tool-call quartile (Q1–Q4); show perfect/partial/zero score rates
- **Visualization**: Stacked bar chart per model per quartile
- **Interpretation**:
  - Perfect-score rate drops Q1→Q4: High effort = harder task (effort doesn't help)
  - Zero-score rate doubles Q1→Q4: Tool-call limit is binding constraint on hard tasks
  - Partial scores rise in Q4: Upper-effort tasks succeed only partially within budget

### Experiment 13: Cross-Model Difficulty Agreement

- **Calculation**: Spearman rank correlation of per-sample scores for each model pair
- **Visualization**: Heatmap with ρ values and significance markers
- **Interpretation**:
  - **High ρ (>0.7)**: Models agree — difficulty is intrinsic to task
  - **Low ρ (<0.3)**: Models struggle differently — complementary strengths, good for ensembles
  - **Within-family > cross-family**: Same-vendor models agree more than different vendors

---

## Domain-Specific Analyses

### Excytin (Incident Response Forensics)

**Domain context**: 8 security incidents, 599 tasks, agents investigate via SQL queries through bash tool.

| Analysis | What it reveals |
|----------|-----------------|
| **Per-Incident Breakdown** (Exp 2) | Score variation across 8 incident types |
| **Submission vs. Checkpoint Gap Heatmap** (Exp 8) | Per-incident × per-model gap showing investigation thoroughness |
| **SQL Query Analysis** (Exp 14) | Classifies all SQL queries into success/large-result/empty/error; reveals query quality differences across models |

**SQL Query Classification**:
- **Success (≤100 rows)**: Manageable, agent can parse
- **Large result (>100 rows)**: Unrefined query; should add LIMIT/WHERE
- **Empty result**: Valid syntax but no matching data (dominant failure mode)
- **Error**: Syntax error, missing table, permission denied

**Key Excytin insights**:
- All models show large positive submission-checkpoint gaps (0.459–0.573) — bypassing investigation
- Bash tool dominates (95–100% of tool calls); Haiku uniquely uses python (~5%)
- Query quality separates models: Opus 79% success rate vs. GPT-5.4-mini 61%
- Empty results are more problematic than syntax errors (agents waste effort on unproductive queries)

### CyBench (CTF Challenges)

**Domain context**: CTF exploitation challenges with multi-checkpoint progressive investigation tracking.

| Analysis | What it reveals |
|----------|-----------------|
| **Per-Challenge Breakdown** (Exp 2) | Score per challenge type |
| **Submission vs. Checkpoint Gap** (Exp 8) | Per-challenge gap showing investigation process |

**CyBench checkpoint progression** (e.g., Labyrinth Linguist):
1. Contextualizing — understanding challenge environment
2. Understanding templating — recognizing SSTI/language context
3. Identifying attack vectors — finding injection points
4. Exploring templates — testing template engines
5. Locating the flag — finding flag file on disk
6. Crafting exploit — building final payload

**Key CyBench insights**:
- All models achieve 1.0 on submission but 0.167–0.500 on checkpoints — solving without demonstrating full process
- Currently 1 sample per model; distribution analyses produce summary tables instead of charts

### CTI Realm (Threat Intelligence & Detection)

**Domain context**: 25 tasks across 3 platforms (Linux, AKS, Cloud), 5 scored checkpoints totaling 10.0 points.

| Analysis | What it reveals |
|----------|-----------------|
| **Per-Platform Breakdown** (Exp 2) | Score variation across Linux/AKS/Cloud |
| **Per-Checkpoint Score Heatmap** (Exp 8) | C0–C4 × Model heatmap showing checkpoint-level performance |
| **CTI Tool Usage & Report Analysis** (Exp 14) | Tool call patterns across 4 categories (KQL/Data, CTI/MITRE, Sigma, General) |
| **KQL Query Quality Analysis** (Exp 15) | Query success/error rates, correlation with F1 scores |
| **Checkpoint Correlation Analysis** (Exp 16) | Independence of C0–C4 checkpoints (validates scoring design) |

**CTI Realm 5-checkpoint scoring**:
- **C0 CTI Alignment** (max 1.25): Did agent use CTI reports? Relevance to objective?
- **C1 MITRE Techniques** (max 0.75): Jaccard similarity of found vs. expected ATT&CK techniques
- **C2 Data Exploration** (max 1.0): Coverage of expected data sources queried
- **C3 Query Iteration** (max 0.5): Binary — did agent run ≥2 unique successful KQL queries?
- **C4 Detection Quality** (max 6.5): KQL F1 (weight 5.0) + Sigma rule quality (weight 1.5)

**CTI Realm tool categories**:
- **KQL/Data** (48%): execute_kql_query, list_kusto_tables, get_table_schema, sample_table_data
- **CTI/MITRE** (29%): list_cti_report_tags, get_cti_reports_by_tag, search_mitre_techniques
- **Sigma/Detection** (13%): search_sigma_rules, validate_output_json
- **General** (10%): bash, python

**Key CTI Realm insights**:
- C4 (Detection Quality) dominates total score (65% of max) but max achieved is ~59%
- Checkpoints are remarkably independent (all pairwise |ρ| < 0.4) — validates scoring design
- C0 (CTI reading) does NOT predict C4 (detection quality) — distinct skills
- More KQL queries don't linearly improve detection: Opus achieves 58% C4 with only 4.6 queries/sample vs. GPT-5.4's 9.7

---

## Agent Architecture Analysis

### Comparison Framework

Agent architecture analysis uses the **same 12 experiments** as model comparison but slices by agent architecture instead of model identity. Primary comparison axis: **React vs. GH Copilot vs. Claude Code** for a fixed model (currently Claude Sonnet 4.6).

### Agent Architecture Findings (Aggregate)

| Metric | React | GH Copilot | Claude Code |
|--------|-------|------------|-------------|
| Aggregate Score | 0.801 ± 0.134 | 0.648 | 0.441 |
| Cost/Sample | $0.251 (cheapest) | $0.350 | $0.420 |
| Reward/$ | 3.19 (highest) | 1.85 | 1.05 |
| Tool Calls/Sample | ~18.8 | ~18.7 | ~18.9 |
| Time/Sample | 3.3 min (fastest) | 5.0 min | 4.2 min |
| Ranking Consistency | 1.0 ± 0.0 (perfect) | 2.33 ± 1.15 (volatile) | 2.67 ± 0.58 |

**Key agent architecture insights**:
- React dominates on score, cost, and consistency across all domains
- All architectures use nearly identical tool-call budgets (~18.8 calls); speed difference is thinking/planning overhead
- Copilot matches React on submission scores (0.846 vs 0.852) but lags on checkpoints (0.380 vs 0.548)
- Claude Code's primary failure mode is invalid final answers (lowest submission score: 0.348)

---

## Cross-Domain Aggregate Analysis

### Normalization Method

Domains have vastly different sample counts (Excytin: 599, CTI Realm: 25, CyBench: 1). To prevent sample-rich domains from dominating:

1. Compute **per-domain mean** for each model/agent on each metric
2. Average per-domain means with **equal weight per domain**

$$\text{Aggregate Score}(m) = \frac{1}{|\mathcal{D}|} \sum_{d \in \mathcal{D}} \overline{\text{score}}(m, d)$$

### Aggregate Experiment Types

| # | Analysis | What it shows |
|---|----------|---------------|
| 1 | Normalized Overall Reward | Domain-weighted mean saber_overall per model |
| 2 | Per-Domain Score Breakdown | Heatmap + grouped bar showing model × domain scores |
| 3 | Normalized Cost Analysis | Per-sample cost averaged across domains; Pareto chart |
| 4 | Normalized Cost Efficiency | Reward per dollar, domain-weighted |
| 5 | Sub-Task Breakdown | Submission/Checkpoints/Aggregate, domain-averaged |
| 6 | Agent Trajectory Efficiency | Tool calls, steps, time (domain-averaged) |
| 7 | Cross-Domain Ranking Consistency | Bump chart: do models rank the same across domains? |
| 8 | Cross-Domain Radar Chart | Spider chart showing per-domain strength per model |
| 9 | Reasoning Impact (models only) | Per-domain reasoning delta aggregated with equal weight |

**Partial coverage**: If a model doesn't appear in all domains, its aggregate is computed over only contributing domains (annotated in charts).

---

## Key Insights Patterns

These are recurring patterns to look for and communicate when interpreting results:

### 1. Cost-Efficiency Trade-offs
- Higher-cost models often provide diminishing returns
- Typical pattern: Haiku (cheapest) → Sonnet (mid) → Opus (high) → GPT (highest)
- Haiku gets 12–18× more reward per dollar than GPT-5.4
- Marginal score gains diminish as cost increases

### 2. Effort vs. Outcome (Non-linear)
- More tool calls do NOT guarantee better scores
- High-effort (Q4) tasks have 15–20% more zero scores than low-effort (Q1) tasks
- Tool-call budget is a binding constraint on hard tasks, not a surplus resource

### 3. Investigation vs. Final Answer Gap
- Submission scores >> Checkpoint scores across ALL domains
- Typical gaps: Excytin 0.459–0.573, CyBench 0.500–0.833
- Models reach correct conclusions without thorough investigation — risky in production
- Models may be using prior knowledge or pattern-matching instead of genuine analysis

### 4. Speed vs. Capability (Model-Family Patterns)
- Claude models: 1.4–2.7 min/sample, lower token budgets
- GPT models: 10+ min/sample (4–6× slower), higher token budgets
- GPT's extended reasoning overhead adds latency without proportional score gains in some domains

### 5. Task Difficulty Varies by Domain Structure
- Easy domains (all models score high): Excytin (0.77–0.88)
- Hard domains (massive variance): CTI Realm (0.26–0.63)
- Domain complexity (tool count, checkpoint interdependencies) drives difficulty ceiling

### 6. Model Agreement on Difficulty
- Spearman correlations moderate (0.4–0.8) — difficulty is partly intrinsic, partly model-dependent
- Same-family models agree more than cross-family (Sonnet↔Opus: ρ=0.64 vs. Claude↔GPT: ρ=0.47–0.53)
- Implication: Ensemble strategies should pair different model families

### 7. Reasoning Impact is Model & Domain-Dependent
- Excytin: Minimal reasoning boost for most models
- CTI Realm: Dramatic reasoning boost for GPT (+0.16–0.18), none for Claude
- Multi-step collaborative workflows benefit more from explicit chain-of-thought

### 8. Architecture Consistency
- React agent: Rank 1 across all domains (perfect consistency)
- GH Copilot: Rank 1–3 depending on domain (volatile)
- Agent architecture choice has domain-dependent trade-offs

---

## Configuration Guide

### Adding a New Model to Analysis

1. **Check if sample evals already exist** — look in `eval_samples/<domain>/` or try running the notebook (it auto-downloads from HuggingFace)
2. **If not available**, run the evaluation:
   ```bash
   uv run inspect eval domains/<domain> --model <api/model-id> --display plain
   ```
3. Copy the `.eval` file to `eval_samples/<domain>/` or `latest_experiments/<domain>/` with a descriptive name
4. Edit the notebook's Configuration cell:
   ```python
   EVAL_LOGS['Display Name'] = 'filename.eval'
   COLORS['Display Name'] = '#HexColor'
   PRICING['api/model-id'] = {'input': X, 'output': Y, 'cache_read': Z, 'cache_write': W}
   ```
5. (Optional) Add a no-reasoning baseline to `NO_THINKING_LOGS`

### Adding a New Domain

1. Create a domain-specific notebook by copying `eval_analysis.ipynb`
2. Define `GROUP_FN` for your domain's sample ID grouping:
   ```python
   # Inspect sample IDs from your .eval files
   # Write a function: sample_id → group_label
   GROUP_FN = lambda id: id.split('_')[0]  # Example
   ```
3. Add domain-specific experiments after the generic 14
4. Register the notebook in the inventory table above

### Adding a New Agent Architecture

1. **Check if sample evals already exist** — look in `eval_samples/<domain>/` for `*_react.eval`, `*_copilot.eval`, `*_claude_code.eval`
2. **If not available**, run evals for each agent:
   ```bash
   uv run inspect eval domains/<domain> --model <model> -T agent=react --display plain
   uv run inspect eval domains/<domain> --model <model> -T agent=copilot --display plain
   ```
3. Add entries to the agent architecture notebook's `AGENT_EVAL_LOGS`
4. Add a color in `AGENT_COLORS`

---

## Artifact Output Structure

Analysis notebooks save visualizations to `notebooks/artifacts/`:

```
notebooks/artifacts/
├── {domain}/                     # Per-domain model comparison
│   ├── overall_reward.png
│   ├── per_{group}_scores.png
│   ├── cost_analysis.png
│   ├── token_usage_breakdown.png
│   ├── cost_efficiency.png
│   ├── subtask_breakdown.png
│   ├── checkpoint_distributions.png
│   ├── submission_checkpoint_gap.png
│   ├── score_vs_tool_call_limit.png
│   ├── effort_distributions.png
│   ├── tool_usage.png
│   ├── steps_vs_reward.png
│   ├── effort_outcome_segmentation.png
│   └── cross_model_correlation.png
│
├── {domain}_agent/               # Per-domain agent architecture comparison
│   ├── overall_reward_by_agent.png
│   ├── cost_analysis_by_agent.png
│   └── ... (same experiment set, sliced by agent)
│
├── aggregate_model/              # Cross-domain model comparison (normalized)
│   ├── aggregate_overall_reward.png
│   ├── per_domain_breakdown.png
│   ├── aggregate_cost_analysis.png
│   ├── aggregate_cost_efficiency.png
│   ├── cross_domain_radar.png
│   ├── ranking_consistency.png
│   └── reasoning_impact.png
│
└── aggregate_agent/              # Cross-domain agent comparison (normalized)
    ├── aggregate_overall_reward.png
    ├── per_domain_breakdown.png
    ├── cross_domain_radar.png
    └── ranking_consistency.png
```

---

## Quick Analysis Recipes

### "Which model should I use for domain X?"

1. Open `notebooks/{domain}_analysis.ipynb`
2. Look at Experiment 1 (overall reward) for raw scores
3. Look at Experiment 5 (cost efficiency) for value
4. Check Experiment 3 (Pareto frontier) for dominated vs. non-dominated models
5. Consider Experiment 11 (time efficiency) if latency matters

### "How do agent architectures compare?"

1. Open `notebooks/aggregate_agent_architecture_analysis.ipynb`
2. Look at overall reward per agent (Exp 1) — React typically dominates
3. Check per-domain breakdown (Exp 2) — some agents may excel in specific domains
4. Review cost analysis (Exp 3) — architecture affects cost
5. Check trajectory efficiency (Exp 6) — same tool calls, different speed

### "Is extended reasoning worth it?"

1. Open the domain-specific notebook with `NO_THINKING_LOGS` configured
2. Look at reasoning delta (hatched bars) in Exp 1
3. Check cost-efficiency impact in Exp 5
4. CTI Realm benefits most from reasoning; Excytin shows minimal impact

### "Why is my model scoring low?"

1. Check Experiment 6 (sub-task breakdown): Submission vs. checkpoint gap reveals whether the model investigates or guesses
2. Check domain-specific analysis: SQL errors (Excytin), KQL quality (CTI Realm), checkpoint progression (CyBench)
3. Check Experiment 9a (effort budget): Is the model running out of tool calls?
4. Check Experiment 12 (effort segmentation): Does the model fail on high-effort tasks?

### "Programmatic analysis without notebooks"

Use the `saber_analysis` library directly:

```python
import sys
sys.path.insert(0, "notebooks")
from saber_analysis import load_eval_logs, extract_cost_rows, setup_plotting

# Load data
overall_df, samples_df, subtasks_df = load_eval_logs(
    eval_logs={'Model A': 'model_a.eval'},
    log_dir='latest_experiments/excytin',
    group_fn=lambda id: '_'.join(id.split('_')[:2]),
)

# Cost analysis
cost_rows = extract_cost_rows(
    log_dict={'Model A': 'model_a.eval'},
    log_dir='latest_experiments/excytin',
    pricing={'anthropic/claude-sonnet-4-6': {'input': 3, 'output': 15, 'cache_read': 0.3, 'cache_write': 3.75}},
    n_samples=599,
)
```
