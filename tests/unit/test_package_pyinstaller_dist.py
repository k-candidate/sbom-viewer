from __future__ import annotations

import importlib.util
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parents[2]
    / "scripts"
    / "package_pyinstaller_dist.py"
)


def load_module():
    spec = importlib.util.spec_from_file_location(
        "package_pyinstaller_dist", MODULE_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_archive_with_ditto_uses_macos_safe_flags(
    monkeypatch, tmp_path: Path
) -> None:
    module = load_module()
    app_dir = tmp_path / "sbom-viewer.app"
    archive_path = tmp_path / "sbom-viewer.zip"
    app_dir.mkdir()
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], check: bool) -> None:
        assert check is True
        calls.append(cmd)

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    module.archive_with_ditto(app_dir, archive_path)

    assert calls == [
        [
            "ditto",
            "-c",
            "-k",
            "--sequesterRsrc",
            "--keepParent",
            str(app_dir),
            str(archive_path),
        ]
    ]


def test_main_uses_ditto_for_macos_archives(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    module = load_module()
    app_dir = tmp_path / "sbom-viewer.app"
    output_dir = tmp_path / "packaged"
    app_dir.mkdir()
    calls: list[tuple[Path, Path]] = []

    def fake_ditto(source: Path, archive: Path) -> None:
        calls.append((source, archive))
        archive.write_text("zip", encoding="utf-8")

    monkeypatch.setattr(module, "archive_with_ditto", fake_ditto)
    monkeypatch.setattr(
        module.shutil,
        "make_archive",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("make_archive should not be used for macOS")
        ),
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "package_pyinstaller_dist.py",
            "--app-dir",
            str(app_dir),
            "--platform-id",
            "macos-arm64",
            "--version",
            "1.1.0",
            "--output-dir",
            str(output_dir),
        ],
    )

    module.main()

    archive_path = output_dir / "sbom-viewer-1.1.0-macos-arm64.zip"
    assert calls == [(app_dir.resolve(), archive_path.resolve())]
    assert capsys.readouterr().out.splitlines() == [
        "sbom-viewer-1.1.0-macos-arm64.zip",
        "sbom-viewer-1.1.0-macos-arm64.zip",
    ]


def test_main_uses_make_archive_for_linux(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    module = load_module()
    app_dir = tmp_path / "sbom-viewer"
    output_dir = tmp_path / "packaged"
    app_dir.mkdir()
    calls: list[tuple[str, str, str, str]] = []

    def fake_make_archive(
        base_name: str, fmt: str, root_dir: str, base_dir: str
    ) -> str:
        calls.append((base_name, fmt, root_dir, base_dir))
        return f"{base_name}.tar.gz"

    monkeypatch.setattr(module.shutil, "make_archive", fake_make_archive)
    monkeypatch.setattr(
        module,
        "archive_with_ditto",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("ditto should not be used for Linux")
        ),
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "package_pyinstaller_dist.py",
            "--app-dir",
            str(app_dir),
            "--platform-id",
            "linux-x64",
            "--version",
            "1.1.0",
            "--output-dir",
            str(output_dir),
        ],
    )

    module.main()

    base_name = str((output_dir / "sbom-viewer-1.1.0-linux-x64").resolve())
    assert calls == [
        (
            base_name,
            "gztar",
            app_dir.parent.resolve(),
            app_dir.name,
        )
    ]
    assert capsys.readouterr().out.splitlines() == [
        "sbom-viewer-1.1.0-linux-x64.tar.gz",
        "sbom-viewer-1.1.0-linux-x64.tar.gz",
    ]


def test_main_uses_make_archive_for_windows(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    module = load_module()
    app_dir = tmp_path / "sbom-viewer"
    output_dir = tmp_path / "packaged"
    app_dir.mkdir()
    calls: list[tuple[str, str, Path, str]] = []

    def fake_make_archive(
        base_name: str, fmt: str, root_dir: Path, base_dir: str
    ) -> str:
        calls.append((base_name, fmt, root_dir, base_dir))
        return f"{base_name}.zip"

    monkeypatch.setattr(module.shutil, "make_archive", fake_make_archive)
    monkeypatch.setattr(
        module,
        "archive_with_ditto",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("ditto should not be used for Windows")
        ),
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "package_pyinstaller_dist.py",
            "--app-dir",
            str(app_dir),
            "--platform-id",
            "windows-x64",
            "--version",
            "1.1.0",
            "--output-dir",
            str(output_dir),
        ],
    )

    module.main()

    base_name = str((output_dir / "sbom-viewer-1.1.0-windows-x64").resolve())
    assert calls == [
        (
            base_name,
            "zip",
            app_dir.parent.resolve(),
            app_dir.name,
        )
    ]
    assert capsys.readouterr().out.splitlines() == [
        "sbom-viewer-1.1.0-windows-x64.zip",
        "sbom-viewer-1.1.0-windows-x64.zip",
    ]
