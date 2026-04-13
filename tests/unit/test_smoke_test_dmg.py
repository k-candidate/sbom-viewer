from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


MODULE_PATH = (
    Path(__file__).resolve().parents[2] / "scripts" / "smoke_test_dmg.py"
)


def load_module():
    spec = importlib.util.spec_from_file_location("smoke_test_dmg", MODULE_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_verify_mounted_layout_accepts_display_name_bundle(tmp_path: Path) -> None:
    module = load_module()
    mount_point = tmp_path / "mount"
    app_dir = mount_point / "SBOM Viewer.app" / "Contents" / "MacOS"
    app_dir.mkdir(parents=True)
    (app_dir / "sbom-viewer").write_text("exe", encoding="utf-8")
    (mount_point / "Applications").symlink_to("/Applications")

    module.verify_mounted_layout(mount_point, "SBOM Viewer.app")


def test_verify_mounted_layout_rejects_missing_app(tmp_path: Path) -> None:
    module = load_module()
    mount_point = tmp_path / "mount"
    mount_point.mkdir()
    (mount_point / "Applications").symlink_to("/Applications")

    with pytest.raises(SystemExit, match="App bundle missing"):
        module.verify_mounted_layout(mount_point, "SBOM Viewer.app")
