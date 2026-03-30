"""Tests for cti_realm.setup — domain setup hooks (Hugging Face download)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from saber.hooks import SetupHook

from cti_realm.setup import (
    DownloadCTIData,
    _KUSTO_FILES,
    _cli_bool,
    download_cti_data,
    get_hooks,
)


# ---------------------------------------------------------------------------
# Helpers to create fake data for should_run tests
# ---------------------------------------------------------------------------


def _create_kusto_data(domain_root: Path) -> None:
    data_dir = domain_root / "docker" / "kusto_init" / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "deviceprocessevents.jsonl").write_text("{}")


def _create_cti_reports(domain_root: Path) -> None:
    reports_dir = domain_root / "data" / "cti_reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / "reports.jsonl").write_text("{}")


def _create_sigma_rules(domain_root: Path) -> None:
    data_dir = domain_root / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "sigma_rules.json").write_text("{}")


# ---------------------------------------------------------------------------
# TestDownloadCTIDataShouldRun
# ---------------------------------------------------------------------------


class TestDownloadCTIDataShouldRun:
    def test_satisfies_protocol(self) -> None:
        assert isinstance(DownloadCTIData(), SetupHook)

    def test_name(self) -> None:
        assert DownloadCTIData().name == "download_cti_data"

    def test_should_run_when_no_data_exists(self, tmp_path: Path) -> None:
        assert DownloadCTIData().should_run(tmp_path) is True

    def test_should_run_when_kusto_data_missing(self, tmp_path: Path) -> None:
        _create_cti_reports(tmp_path)
        _create_sigma_rules(tmp_path)
        assert DownloadCTIData().should_run(tmp_path) is True

    def test_should_run_when_cti_reports_missing(self, tmp_path: Path) -> None:
        _create_kusto_data(tmp_path)
        _create_sigma_rules(tmp_path)
        assert DownloadCTIData().should_run(tmp_path) is True

    def test_should_run_when_sigma_rules_missing(self, tmp_path: Path) -> None:
        _create_kusto_data(tmp_path)
        _create_cti_reports(tmp_path)
        assert DownloadCTIData().should_run(tmp_path) is True

    def test_should_not_run_when_all_data_present(self, tmp_path: Path) -> None:
        _create_kusto_data(tmp_path)
        _create_cti_reports(tmp_path)
        _create_sigma_rules(tmp_path)
        assert DownloadCTIData().should_run(tmp_path) is False

    def test_force_download_always_runs(self, tmp_path: Path) -> None:
        _create_kusto_data(tmp_path)
        _create_cti_reports(tmp_path)
        _create_sigma_rules(tmp_path)
        assert DownloadCTIData(force_download=True).should_run(tmp_path) is True

    def test_should_run_when_kusto_dir_exists_but_empty(self, tmp_path: Path) -> None:
        kusto_dir = tmp_path / "docker" / "kusto_init" / "data"
        kusto_dir.mkdir(parents=True)
        _create_cti_reports(tmp_path)
        _create_sigma_rules(tmp_path)
        assert DownloadCTIData().should_run(tmp_path) is True


# ---------------------------------------------------------------------------
# TestGetHooks
# ---------------------------------------------------------------------------


class TestGetHooks:
    def test_returns_single_hook(self) -> None:
        hooks = get_hooks(Path("/unused"))
        assert len(hooks) == 2
        assert all(isinstance(h, SetupHook) for h in hooks)

    def test_first_hook_is_download_cti_data(self) -> None:
        hooks = get_hooks(Path("/unused"))
        assert isinstance(hooks[0], DownloadCTIData)

    def test_forwards_force_download_flag(self) -> None:
        hooks = get_hooks(Path("/unused"), force_download="true")
        assert hooks[0]._force_download is True

    def test_defaults(self) -> None:
        hooks = get_hooks(Path("/unused"))
        assert hooks[0]._force_download is False

    def test_unknown_kwargs_ignored(self) -> None:
        hooks = get_hooks(Path("/unused"), task_filter="incident_*", agent="default")
        assert len(hooks) == 2


# ---------------------------------------------------------------------------
# TestDownloadCTIDataRun
# ---------------------------------------------------------------------------


class TestDownloadCTIDataRun:
    def test_run_calls_download_function(self, tmp_path: Path) -> None:
        hook = DownloadCTIData()
        with patch("cti_realm.setup.download_cti_data") as mock_dl:
            hook.run(tmp_path)
            mock_dl.assert_called_once_with(tmp_path, force_download=False)

    def test_run_forwards_force_download(self, tmp_path: Path) -> None:
        hook = DownloadCTIData(force_download=True)
        with patch("cti_realm.setup.download_cti_data") as mock_dl:
            hook.run(tmp_path)
            mock_dl.assert_called_once_with(tmp_path, force_download=True)

    def test_run_raises_on_missing_hf_hub(self, tmp_path: Path) -> None:
        with patch.dict("sys.modules", {"huggingface_hub": None}):
            with pytest.raises(ImportError, match="huggingface_hub"):
                download_cti_data(tmp_path)


# ---------------------------------------------------------------------------
# TestCliBool
# ---------------------------------------------------------------------------


class TestCliBool:
    def test_none_returns_default(self) -> None:
        assert _cli_bool(None) is False
        assert _cli_bool(None, default=True) is True

    def test_true_string(self) -> None:
        assert _cli_bool("true") is True

    def test_false_string(self) -> None:
        assert _cli_bool("false") is False

    def test_bool_passthrough(self) -> None:
        assert _cli_bool(True) is True
        assert _cli_bool(False) is False

    def test_one_and_yes(self) -> None:
        assert _cli_bool("1") is True
        assert _cli_bool("yes") is True


# ---------------------------------------------------------------------------
# TestDownloadCTIDataDetails
# ---------------------------------------------------------------------------


class TestDownloadCTIDataDetails:
    def _mock_hf_download(self, tmp_path: Path, content: bytes = b"mock-data") -> MagicMock:
        """Create a mock hf_hub_download that writes temp files."""
        cache_dir = tmp_path / ".hf_cache"
        cache_dir.mkdir(parents=True, exist_ok=True)

        def fake_download(*, repo_id, filename, repo_type, local_dir, token, revision):
            cached = cache_dir / filename.replace("/", "_")
            cached.write_bytes(content)
            return str(cached)

        return MagicMock(side_effect=fake_download)

    def _patch_hf(self, mock_dl: MagicMock):
        """Patch hf_hub_download at the huggingface_hub module level."""
        mock_module = MagicMock()
        mock_module.hf_hub_download = mock_dl
        return patch.dict("sys.modules", {"huggingface_hub": mock_module})

    def test_existing_files_skipped_when_no_force(self, tmp_path: Path) -> None:
        mock_dl = self._mock_hf_download(tmp_path)

        kusto_dir = tmp_path / "docker" / "kusto_init" / "data"
        kusto_dir.mkdir(parents=True)
        (kusto_dir / "signinlogs.jsonl").write_bytes(b"old")

        reports_dir = tmp_path / "data" / "cti_reports"
        reports_dir.mkdir(parents=True)
        (reports_dir / "reports.jsonl").write_bytes(b"old")

        with self._patch_hf(mock_dl):
            download_cti_data(tmp_path, force_download=False)

        downloaded_filenames = [
            call.kwargs["filename"] for call in mock_dl.call_args_list
        ]
        assert not any(f.endswith("/signinlogs.jsonl") for f in downloaded_filenames)
        assert not any(f.endswith("/reports.jsonl") for f in downloaded_filenames)
        assert any("aksaudit.jsonl" in f for f in downloaded_filenames)

    def test_force_download_redownloads_existing(self, tmp_path: Path) -> None:
        mock_dl = self._mock_hf_download(tmp_path)

        _create_kusto_data(tmp_path)
        _create_cti_reports(tmp_path)
        _create_sigma_rules(tmp_path)

        with self._patch_hf(mock_dl):
            download_cti_data(tmp_path, force_download=True)

        assert mock_dl.call_count == 18  # 12 kusto + reports + sigma + 4 dataset JSONL

    def test_all_categories_create_directories(self, tmp_path: Path) -> None:
        mock_dl = self._mock_hf_download(tmp_path)
        with self._patch_hf(mock_dl):
            download_cti_data(tmp_path)

        assert (tmp_path / "docker" / "kusto_init" / "data").is_dir()
        assert (tmp_path / "data" / "cti_reports").is_dir()
        assert (tmp_path / "data").is_dir()

    def test_files_written_to_expected_paths(self, tmp_path: Path) -> None:
        content = b"test-hf-data-12345"
        mock_dl = self._mock_hf_download(tmp_path, content=content)
        with self._patch_hf(mock_dl):
            download_cti_data(tmp_path)

        kusto_dir = tmp_path / "docker" / "kusto_init" / "data"
        for filename in _KUSTO_FILES:
            path = kusto_dir / filename
            assert path.exists(), f"Missing kusto file: {filename}"
            assert path.read_bytes() == content

        assert (tmp_path / "data" / "cti_reports" / "reports.jsonl").exists()
        assert (tmp_path / "data" / "sigma_rules.json").exists()


# ---------------------------------------------------------------------------
# TestDownloadCTIDataErrorHandling
# ---------------------------------------------------------------------------


class TestDownloadCTIDataErrorHandling:
    def test_single_file_failure_continues_downloads(self, tmp_path: Path) -> None:
        cache_dir = tmp_path / ".hf_cache"
        cache_dir.mkdir(parents=True, exist_ok=True)

        def fake_download(*, repo_id, filename, repo_type, local_dir, token, revision):
            if "aksaudit.jsonl" in filename:
                raise RuntimeError("network error")
            cached = cache_dir / filename.replace("/", "_")
            cached.write_bytes(b"ok")
            return str(cached)

        mock_module = MagicMock()
        mock_module.hf_hub_download = MagicMock(side_effect=fake_download)
        with patch.dict("sys.modules", {"huggingface_hub": mock_module}):
            with pytest.raises(RuntimeError, match="1 error"):
                download_cti_data(tmp_path)

    def test_no_errors_no_exception(self, tmp_path: Path) -> None:
        cache_dir = tmp_path / ".hf_cache"
        cache_dir.mkdir(parents=True, exist_ok=True)

        def fake_download(*, repo_id, filename, repo_type, local_dir, token, revision):
            cached = cache_dir / filename.replace("/", "_")
            cached.write_bytes(b"ok")
            return str(cached)

        mock_module = MagicMock()
        mock_module.hf_hub_download = MagicMock(side_effect=fake_download)
        with patch.dict("sys.modules", {"huggingface_hub": mock_module}):
            download_cti_data(tmp_path)  # Should not raise
