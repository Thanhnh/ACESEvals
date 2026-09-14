"""SABER-SIM domain setup hooks."""
from __future__ import annotations
import hashlib
import shutil
import tempfile
import zipfile
from pathlib import Path
import yaml
from saber.hooks import SetupHook
from saber.logging import get_logger

logger = get_logger("domains.saber_sim.setup")

_LOG_MANIFEST = "range_logs.yaml"

def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def _safe_extract(archive: Path, target_dir: Path) -> None:
    target_root = target_dir.resolve()
    with zipfile.ZipFile(archive) as zf:
        members: list[tuple[zipfile.ZipInfo, Path]] = []
        for member in zf.infolist():
            target = (target_root / member.filename).resolve()
            if target != target_root and target_root not in target.parents:
                raise ValueError(f"Unsafe path in range-log archive: {member.filename!r}")
            if (member.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError(f"Symlink blocked in range-log archive: {member.filename!r}")
            members.append((member, target))
        for member, target in members:
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as src, target.open("wb") as dst:
                    shutil.copyfileobj(src, dst)

class MaterializeRangeLogs(SetupHook):
    @property
    def name(self) -> str:
        return "materialize_range_logs"

    def _manifests(self, domain_root: Path) -> list[Path]:
        scenarios = domain_root / "docker" / "scenarios"
        return sorted(scenarios.glob(f"*/{_LOG_MANIFEST}")) if scenarios.is_dir() else []

    def should_run(self, domain_root: Path) -> bool:
        return any(
            not any((manifest.parent / "logs").rglob("*.jsonl"))
            for manifest in self._manifests(domain_root)
        )

    def run(self, domain_root: Path) -> None:
        try:
            from huggingface_hub import hf_hub_download
        except ImportError as exc:
            raise ImportError(
                "huggingface_hub is required to materialize SABER-Sim range logs"
            ) from exc

        for manifest_path in self._manifests(domain_root):
            logs_dir = manifest_path.parent / "logs"
            if any(logs_dir.rglob("*.jsonl")):
                continue
            manifest = yaml.safe_load(manifest_path.read_text())
            archive_path = Path(hf_hub_download(
                repo_id=manifest["repo_id"],
                repo_type="dataset",
                filename=manifest["filename"],
                revision=manifest["revision"],
            ))
            actual = _sha256(archive_path)
            expected = manifest["sha256"]
            if actual != expected:
                raise ValueError(
                    f"Range-log digest mismatch for {manifest_path.parent.name}: "
                    f"expected {expected}, got {actual}"
                )
            with tempfile.TemporaryDirectory(dir=manifest_path.parent) as temp_dir:
                extracted = Path(temp_dir) / "logs"
                extracted.mkdir()
                _safe_extract(archive_path, extracted)
                files = list(extracted.rglob("*.jsonl"))
                if len(files) != manifest["file_count"]:
                    raise RuntimeError(
                        f"Expected {manifest['file_count']} range-log files, got {len(files)}"
                    )
                if logs_dir.exists():
                    shutil.rmtree(logs_dir)
                extracted.replace(logs_dir)
            logger.info("Materialized range logs: %s", manifest_path.parent.name)

class SelectScenarioCompose(SetupHook):
    def __init__(self, task_filter: str | None = None) -> None:
        self._task_filter = task_filter

    @property
    def name(self) -> str:
        return "select_scenario_compose"

    def should_run(self, domain_root: Path) -> bool:
        if not self._task_filter:
            return False
        compose_dir = domain_root / "compose"
        return compose_dir.is_dir() and any(
            f.name != "sandbox.compose.yaml" and f.name.endswith(".compose.yaml")
            for f in compose_dir.iterdir()
        )

    def run(self, domain_root: Path) -> None:
        compose_dir = domain_root / "compose"
        sandbox_path = compose_dir / "sandbox.compose.yaml"
        raw = self._task_filter or ""
        patterns = raw if isinstance(raw, list) else str(raw).split(",")
        prefixes = [p.strip().rstrip("*").rstrip("_") for p in patterns if p.strip()]
        candidates = []
        for f in sorted(compose_dir.iterdir()):
            if f.name == "sandbox.compose.yaml" or not f.name.endswith(".compose.yaml"):
                continue
            scenario_name = f.name.removesuffix(".compose.yaml")
            if any(scenario_name.startswith(p) or p.startswith(scenario_name) for p in prefixes):
                candidates.append(f)
        if len(candidates) == 1:
            selected = candidates[0]
            scenario_name = selected.name.removesuffix(".compose.yaml")
            if sandbox_path.exists() and sandbox_path.read_text().strip() == selected.read_text().strip():
                return
            shutil.copy2(selected, sandbox_path)
            yml_link = compose_dir / "sandbox.compose.yml"
            if yml_link.exists() or yml_link.is_symlink():
                yml_link.unlink()
            try:
                yml_link.symlink_to("sandbox.compose.yaml")
            except OSError:
                shutil.copy2(sandbox_path, yml_link)
            logger.info("Activated scenario compose: %s", scenario_name)

def get_hooks(domain_root: Path, *, task_filter: str | None = None, **kwargs: object) -> list[SetupHook]:
    return [MaterializeRangeLogs(), SelectScenarioCompose(task_filter=task_filter)]
