from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts" / "build_deb.py"


def load_module():
    spec = importlib.util.spec_from_file_location("build_deb", MODULE_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_find_app_dir_returns_executable_parent(tmp_path: Path) -> None:
    module = load_module()
    app_dir = tmp_path / "sbom-viewer"
    app_dir.mkdir()
    (app_dir / "sbom-viewer").write_text("exe", encoding="utf-8")

    assert module.find_app_dir(tmp_path) == app_dir


def test_find_app_dir_rejects_missing_executable(tmp_path: Path) -> None:
    module = load_module()

    with pytest.raises(SystemExit, match="No sbom-viewer found"):
        module.find_app_dir(tmp_path)


def test_find_app_dir_rejects_multiple_executables(tmp_path: Path) -> None:
    module = load_module()
    one = tmp_path / "one"
    two = tmp_path / "two"
    one.mkdir()
    two.mkdir()
    (one / "sbom-viewer").write_text("exe", encoding="utf-8")
    (two / "sbom-viewer").write_text("exe", encoding="utf-8")

    with pytest.raises(SystemExit, match="Expected exactly one sbom-viewer"):
        module.find_app_dir(tmp_path)


def test_installer_arch_maps_supported_platforms() -> None:
    module = load_module()
    assert module.installer_arch("linux-x64") == "amd64"
    assert module.installer_arch("linux-arm64") == "arm64"


def test_installer_arch_rejects_other_platforms() -> None:
    module = load_module()
    with pytest.raises(SystemExit, match="Unsupported Linux platform id"):
        module.installer_arch("windows-x64")
    with pytest.raises(SystemExit, match="Unsupported Linux platform id"):
        module.installer_arch("macos-arm64")


def test_generate_control_file() -> None:
    module = load_module()
    control = module.generate_control_file("1.2.3", "amd64")
    assert "Package: sbom-viewer" in control
    assert "Version: 1.2.3" in control
    assert "Architecture: amd64" in control
    assert "Maintainer:" in control
    assert "Homepage:" in control
    assert "Description:" in control


def test_generate_desktop_file() -> None:
    module = load_module()
    desktop = module.generate_desktop_file()
    assert "[Desktop Entry]" in desktop
    assert "Name=SBOM Viewer" in desktop
    assert "Exec=/usr/bin/sbom-viewer" in desktop
    assert "Icon=sbom-viewer" in desktop
    assert "Categories=Utility;" in desktop


def test_generate_postinst_script() -> None:
    module = load_module()
    script = module.generate_postinst_script()
    assert "#!/bin/bash" in script
    assert "/usr/bin/sbom-viewer" in script
    assert "ln -sf" in script


def test_generate_prerm_script() -> None:
    module = load_module()
    script = module.generate_prerm_script()
    assert "#!/bin/bash" in script
    assert "rm -f /usr/bin/sbom-viewer" in script
