"""CTI Realm domain setup hooks.

Provides two setup hooks that run automatically before evaluation:

1. ``DownloadCTIData`` — downloads infrastructure data + dataset JSONL
   files from Hugging Face if not already present locally.
2. ``GenerateTaskYAML`` — generates task YAML files from the downloaded
   JSONL datasets (so you don't have to maintain 2000+ line YAML files
   by hand).

Data categories downloaded:
  - Kusto telemetry data (JSONL files for Kusto emulator)
  - CTI reports (reports.jsonl)
  - Sigma rules (sigma_rules.json)
  - Dataset definitions (samples + answers JSONL for 25/50 variants)
"""

from __future__ import annotations

import shutil
from pathlib import Path

from saber.hooks import SetupHook
from saber.logging import get_logger

logger = get_logger("domains.cti_realm.setup")

# ---------------------------------------------------------------------------
# Hugging Face dataset repository
# ---------------------------------------------------------------------------
HF_REPO = "arjun180-new/cti_realm"
HF_REVISION = "0fa6744b0e1d8b5b65cad0d5356a8e968bd22b02"

# ---------------------------------------------------------------------------
# Local directory layout (relative to domain_root)
# ---------------------------------------------------------------------------
_KUSTO_DATA_DIR = "docker/kusto_init/data"
_CTI_REPORTS_DIR = "data/cti_reports"
_SIGMA_RULES_DIR = "data"
_DATASET_DIR = "data"

# ---------------------------------------------------------------------------
# HF repo path → (local_subdir relative to domain_root, local_filename)
# ---------------------------------------------------------------------------
_HF_FILES: dict[str, tuple[str, str]] = {
    # Kusto telemetry data
    "cti_realm/kusto_data/aadserviceprincipalsigninlogs.jsonl": (_KUSTO_DATA_DIR, "aadserviceprincipalsigninlogs.jsonl"),
    "cti_realm/kusto_data/aksaudit.jsonl": (_KUSTO_DATA_DIR, "aksaudit.jsonl"),
    "cti_realm/kusto_data/aksauditadmin.jsonl": (_KUSTO_DATA_DIR, "aksauditadmin.jsonl"),
    "cti_realm/kusto_data/auditlogs.jsonl": (_KUSTO_DATA_DIR, "auditlogs.jsonl"),
    "cti_realm/kusto_data/azureactivity.jsonl": (_KUSTO_DATA_DIR, "azureactivity.jsonl"),
    "cti_realm/kusto_data/azurediagnostics.jsonl": (_KUSTO_DATA_DIR, "azurediagnostics.jsonl"),
    "cti_realm/kusto_data/devicefileevents.jsonl": (_KUSTO_DATA_DIR, "devicefileevents.jsonl"),
    "cti_realm/kusto_data/deviceprocessevents.jsonl": (_KUSTO_DATA_DIR, "deviceprocessevents.jsonl"),
    "cti_realm/kusto_data/microsoftgraphactivitylogs.jsonl": (_KUSTO_DATA_DIR, "microsoftgraphactivitylogs.jsonl"),
    "cti_realm/kusto_data/officeactivity.jsonl": (_KUSTO_DATA_DIR, "officeactivity.jsonl"),
    "cti_realm/kusto_data/signinlogs.jsonl": (_KUSTO_DATA_DIR, "signinlogs.jsonl"),
    "cti_realm/kusto_data/storageboblogs.jsonl": (_KUSTO_DATA_DIR, "storageboblogs.jsonl"),
    # CTI reports
    "cti_realm/cti_reports/reports.jsonl": (_CTI_REPORTS_DIR, "reports.jsonl"),
    # Sigma rules
    "cti_realm/data/sigma_rules.json": (_SIGMA_RULES_DIR, "sigma_rules.json"),
    # Dataset definition files (samples + answers for task generation)
    "cti_realm/data/dataset_samples_stratified_25.jsonl": (_DATASET_DIR, "dataset_samples_stratified_25.jsonl"),
    "cti_realm/data/dataset_answers_stratified_25.jsonl": (_DATASET_DIR, "dataset_answers_stratified_25.jsonl"),
    "cti_realm/data/dataset_samples_stratified_50.jsonl": (_DATASET_DIR, "dataset_samples_stratified_50.jsonl"),
    "cti_realm/data/dataset_answers_stratified_50.jsonl": (_DATASET_DIR, "dataset_answers_stratified_50.jsonl"),
}

# Kusto filenames (for should_run checks)
_KUSTO_FILES: tuple[str, ...] = tuple(
    filename for subdir, filename in _HF_FILES.values() if subdir == _KUSTO_DATA_DIR
)


def download_cti_data(
    domain_root: Path,
    *,
    force_download: bool = False,
    token: str | None = None,
) -> None:
    """Download CTI Realm data from Hugging Face.

    Downloads three categories of data:
      1. Kusto telemetry JSONL files
      2. CTI reports (reports.jsonl)
      3. Sigma rules (sigma_rules.json)

    Args:
        domain_root: Path to the CTI Realm domain root directory.
        force_download: If True, download even if files already exist.
        token: Optional Hugging Face API token for private repos.

    Raises:
        ImportError: If ``huggingface_hub`` is not installed.
        RuntimeError: If any downloads fail.
    """
    try:
        from huggingface_hub import hf_hub_download
    except ImportError as exc:
        raise ImportError(
            "huggingface_hub is required for CTI Realm data download. "
            "Install with: pip install huggingface_hub"
        ) from exc

    logger.info("Downloading CTI Realm data from %s", HF_REPO)
    cache_dir = domain_root / ".hf_cache"
    errors: list[str] = []

    for hf_path, (local_subdir, local_filename) in _HF_FILES.items():
        local_dir = domain_root / local_subdir
        local_path = local_dir / local_filename

        if not force_download and local_path.exists():
            logger.info("  Skipping %s (already exists)", local_filename)
            continue

        local_dir.mkdir(parents=True, exist_ok=True)

        try:
            logger.info("  Downloading %s", local_filename)
            downloaded = hf_hub_download(
                repo_id=HF_REPO,
                filename=hf_path,
                repo_type="dataset",
                local_dir=str(cache_dir),
                token=token,
                revision=HF_REVISION,
            )
            shutil.copy2(downloaded, local_path)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{hf_path}: {exc}")
            logger.warning("  Failed to download %s: %s", hf_path, exc)

    if errors:
        summary = "; ".join(errors)
        logger.warning(
            "CTI Realm data download completed with %d error(s): %s",
            len(errors),
            summary,
        )
        raise RuntimeError(
            f"CTI Realm data download had {len(errors)} error(s): {summary}"
        )

    logger.info("CTI Realm data download complete")


def _has_kusto_data(domain_root: Path) -> bool:
    """Check if Kusto telemetry data directory has at least one .jsonl file."""
    kusto_dir = domain_root / _KUSTO_DATA_DIR
    if not kusto_dir.exists():
        return False
    return any(kusto_dir.glob("*.jsonl"))


def _has_cti_reports(domain_root: Path) -> bool:
    """Check if CTI reports file exists."""
    return (domain_root / _CTI_REPORTS_DIR / "reports.jsonl").exists()


def _has_sigma_rules(domain_root: Path) -> bool:
    """Check if sigma rules file exists."""
    return (domain_root / _SIGMA_RULES_DIR / "sigma_rules.json").exists()


class DownloadCTIData:
    """Setup hook that downloads CTI Realm data if not present.

    Satisfies the ``saber.hooks.SetupHook`` protocol. Checks whether
    all three data categories are present locally. If any are missing,
    the hook triggers a download from Hugging Face.

    Args:
        force_download: Always run the download regardless of local state.
    """

    def __init__(self, *, force_download: bool = False) -> None:
        self._force_download = force_download

    @property
    def name(self) -> str:
        """Human-readable hook name."""
        return "download_cti_data"

    def should_run(self, domain_root: Path) -> bool:
        """Return True if any data category is missing or force_download is set."""
        if self._force_download:
            return True
        if not _has_kusto_data(domain_root):
            return True
        if not _has_cti_reports(domain_root):
            return True
        if not _has_sigma_rules(domain_root):
            return True
        return False

    def run(self, domain_root: Path) -> None:
        """Download CTI Realm data from Hugging Face."""
        download_cti_data(
            domain_root,
            force_download=self._force_download,
        )


# ---------------------------------------------------------------------------
# Task YAML generation hook
# ---------------------------------------------------------------------------

_TASK_SIZES = (25, 50)


def _has_task_yaml(domain_root: Path, size: int) -> bool:
    """Check if task YAML file exists for a given variant size."""
    return (domain_root / "tasks" / f"cti_realm_{size}" / f"cti_realm_{size}.yaml").exists()


def _has_dataset_jsonl(domain_root: Path, size: int) -> bool:
    """Check if both JSONL files exist for a given variant size."""
    data_dir = domain_root / _DATASET_DIR
    return (
        (data_dir / f"dataset_samples_stratified_{size}.jsonl").exists()
        and (data_dir / f"dataset_answers_stratified_{size}.jsonl").exists()
    )


class GenerateTaskYAML:
    """Setup hook that generates task YAML files from downloaded JSONL datasets.

    Runs after ``DownloadCTIData`` to produce
    ``tasks/cti_realm_{N}/cti_realm_{N}.yaml`` from the JSONL files.
    Skips generation if the YAML already exists (unless force_generate).
    """

    def __init__(self, *, force_generate: bool = False) -> None:
        self._force_generate = force_generate

    @property
    def name(self) -> str:
        return "generate_task_yaml"

    def should_run(self, domain_root: Path) -> bool:
        if self._force_generate:
            return True
        return any(
            _has_dataset_jsonl(domain_root, size) and not _has_task_yaml(domain_root, size)
            for size in _TASK_SIZES
        )

    def run(self, domain_root: Path) -> None:
        from .scripts.generate_tasks import generate_tasks

        data_dir = domain_root / _DATASET_DIR
        for size in _TASK_SIZES:
            if not _has_dataset_jsonl(domain_root, size):
                logger.info("Skipping cti_realm_%d generation (JSONL not downloaded yet)", size)
                continue
            if not self._force_generate and _has_task_yaml(domain_root, size):
                logger.info("Skipping cti_realm_%d generation (YAML already exists)", size)
                continue
            output_dir = domain_root / "tasks" / f"cti_realm_{size}"
            logger.info("Generating task YAML for cti_realm_%d", size)
            generate_tasks(data_dir, size, output_dir)


def _cli_bool(value: str | bool | None, default: bool = False) -> bool:
    """Coerce a CLI string to a boolean.

    Truthy strings: ``"true"``, ``"1"``, ``"yes"`` (case-insensitive).
    """
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).lower() in {"true", "1", "yes"}


def get_hooks(
    domain_root: Path,  # noqa: ARG001
    **kwargs: object,
) -> list[SetupHook]:
    """Return CTI Realm setup hooks for auto-discovery.

    Recognized ``-T`` flags (passed as *kwargs*):

    * ``force_download`` — ``"true"`` / ``"false"`` (default: false).
    * ``force_generate`` — ``"true"`` / ``"false"`` (default: false).
    """
    force_download = _cli_bool(
        kwargs.get("force_download"),  # type: ignore[arg-type]
        default=False,
    )
    force_generate = _cli_bool(
        kwargs.get("force_generate"),  # type: ignore[arg-type]
        default=False,
    )
    return [
        DownloadCTIData(force_download=force_download),
        GenerateTaskYAML(force_generate=force_generate),
    ]
