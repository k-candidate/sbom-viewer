from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts" / "build_dmg.py"


def load_module():
    spec = importlib.util.spec_from_file_location("build_dmg", MODULE_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_find_app_bundle_returns_single_bundle(tmp_path: Path) -> None:
    module = load_module()
    app_bundle = tmp_path / "sbom-viewer.app"
    app_bundle.mkdir()

    assert module.find_app_bundle(tmp_path) == app_bundle


def test_find_app_bundle_rejects_missing_bundle(tmp_path: Path) -> None:
    module = load_module()

    with pytest.raises(SystemExit, match="No \\.app bundle found"):
        module.find_app_bundle(tmp_path)


def test_find_app_bundle_rejects_multiple_bundles(tmp_path: Path) -> None:
    module = load_module()
    (tmp_path / "one.app").mkdir()
    (tmp_path / "two.app").mkdir()

    with pytest.raises(SystemExit, match="Expected exactly one \\.app bundle"):
        module.find_app_bundle(tmp_path)
