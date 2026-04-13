from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts" / "build_msi.py"


def load_module():
    spec = importlib.util.spec_from_file_location("build_msi", MODULE_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_find_app_dir_returns_executable_parent(tmp_path: Path) -> None:
    module = load_module()
    app_dir = tmp_path / "sbom-viewer"
    app_dir.mkdir()
    (app_dir / "sbom-viewer.exe").write_text("exe", encoding="utf-8")

    assert module.find_app_dir(tmp_path) == app_dir


def test_find_app_dir_rejects_missing_executable(tmp_path: Path) -> None:
    module = load_module()

    with pytest.raises(SystemExit, match="No sbom-viewer\\.exe found"):
        module.find_app_dir(tmp_path)


def test_find_app_dir_rejects_multiple_executables(tmp_path: Path) -> None:
    module = load_module()
    one = tmp_path / "one"
    two = tmp_path / "two"
    one.mkdir()
    two.mkdir()
    (one / "sbom-viewer.exe").write_text("exe", encoding="utf-8")
    (two / "sbom-viewer.exe").write_text("exe", encoding="utf-8")

    with pytest.raises(SystemExit, match="Expected exactly one sbom-viewer\\.exe"):
        module.find_app_dir(tmp_path)


def test_installer_arch_maps_supported_platforms() -> None:
    module = load_module()

    assert module.installer_arch("windows-x64") == "x64"
    assert module.installer_arch("windows-arm64") == "arm64"


def test_installer_arch_rejects_other_platforms() -> None:
    module = load_module()

    with pytest.raises(SystemExit, match="Unsupported Windows platform id"):
        module.installer_arch("linux-x64")


def test_build_wxs_includes_shortcut_entries(tmp_path: Path) -> None:
    module = load_module()
    app_dir = tmp_path / "sbom-viewer"
    wxs_path = tmp_path / "sbom-viewer.wxs"
    (app_dir / "_internal").mkdir(parents=True)
    (app_dir / "sbom-viewer.exe").write_text("exe", encoding="utf-8")
    (app_dir / "_internal" / "base_library.zip").write_text(
        "zip", encoding="utf-8"
    )

    module.build_wxs(app_dir, "1.2.3", wxs_path)

    text = wxs_path.read_text(encoding="utf-8")
    assert 'Name="SBOM Viewer"' in text
    assert "ApplicationStartMenuShortcut" in text
    assert "ApplicationDesktopShortcut" in text
    assert "INSTALLDESKTOPSHORTCUT" in text
