# CTI Detection Task Files

This directory contains YAML task definitions for the CTI Realm domain evaluation.

## Dataset Variants

| Dataset | Samples | Linux | AKS | Cloud | Task definitions |
|---|---:|---:|---:|---:|---|
| `cti_realm_25` (default) | 25 | 15 | 6 | 4 | [cti_realm_25.yaml](cti_realm_25/cti_realm_25.yaml) |
| `cti_realm_50` | 50 | 25 | 17 | 8 | [cti_realm_50.yaml](cti_realm_50/cti_realm_50.yaml) |

The 25-sample dataset is a subset of the 50-sample dataset. There are **50 unique scenarios**, not 75 or 100. These are two dataset selections within one SABER domain, not two individual evaluation samples.

[global.yaml](global.yaml) defines the default dataset and common configuration. Each dataset directory contains its own `shared.yaml` with sandbox and service configuration.

```bash
# Default 25-sample dataset
uv run inspect eval domains/cti_realm --model openai/azure/gpt-4.1

# Full 50-sample dataset
uv run inspect eval domains/cti_realm --model openai/azure/gpt-4.1 \
  -T dataset=cti_realm_50
```

## Generation

The [setup hooks](../setup.py) download the pinned dataset files and invoke the [task generator](../scripts/generate_tasks.py) when task YAML is missing.

For each size `N` (25 or 50), generation joins these domain-relative files by `id`:

- `data/dataset_samples_stratified_N.jsonl`: simulation and ground-truth metadata.
- `data/dataset_answers_stratified_N.jsonl`: detection descriptions.

The output is `tasks/cti_realm_N/cti_realm_N.yaml`.

## Task Filtering

Select individual scenarios within a dataset using `task_filter`:

```bash
# Linux scenarios from the full dataset
uv run inspect eval domains/cti_realm --model openai/azure/gpt-4.1 \
  -T dataset=cti_realm_50 -T task_filter="linux_*"

# One scenario from the default dataset
uv run inspect eval domains/cti_realm --model openai/azure/gpt-4.1 \
  -T task_filter="linux_001"
```

See the [domain README](../README.md#scoring) for the C0-C4 scoring description.
