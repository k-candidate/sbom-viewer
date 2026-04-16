from __future__ import annotations

import argparse
import subprocess
import tempfile
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create a macOS DMG from a PyInstaller app archive."
    )
    parser.add_argument("--app-archive", required=True)
    parser.add_argument("--output-path", required=True)
    parser.add_argument("--volume-name", required=True)
    return parser


def extract_archive(archive_path: Path, destination: Path) -> None:
    subprocess.run(
        ["ditto", "-x", "-k", str(archive_path), str(destination)],
        check=True,
    )


def find_app_bundle(root: Path) -> Path:
    app_bundles = sorted(root.rglob("*.app"))
    if not app_bundles:
        raise SystemExit(f"No .app bundle found in extracted archive: {root}")
    if len(app_bundles) > 1:
        raise SystemExit(
            f"Expected exactly one .app bundle in extracted archive, found {len(app_bundles)}"
        )
    return app_bundles[0]


def copy_app_bundle(source: Path, destination: Path) -> None:
    subprocess.run(["ditto", str(source), str(destination)], check=True)


def create_dmg(stage_dir: Path, output_path: Path, volume_name: str) -> None:
    if output_path.exists():
        output_path.unlink()
    subprocess.run(
        [
            "hdiutil",
            "create",
            "-volname",
            volume_name,
            "-srcfolder",
            str(stage_dir),
            "-ov",
            "-format",
            "UDZO",
            str(output_path),
        ],
        check=True,
    )


def main() -> None:
    args = build_parser().parse_args()
    archive_path = Path(args.app_archive).resolve()
    output_path = Path(args.output_path).resolve()

    if not archive_path.is_file():
        raise SystemExit(f"App archive does not exist: {archive_path}")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="sbom-viewer-dmg-") as tempdir:
        temp_path = Path(tempdir)
        extract_dir = temp_path / "extracted"
        stage_dir = temp_path / "staged"
        extract_dir.mkdir()
        stage_dir.mkdir()

        extract_archive(archive_path, extract_dir)
        app_bundle = find_app_bundle(extract_dir)
        staged_app = stage_dir / app_bundle.name
        copy_app_bundle(app_bundle, staged_app)
        (stage_dir / "Applications").symlink_to("/Applications")

        create_dmg(stage_dir, output_path, args.volume_name)

    print(output_path.name)


if __name__ == "__main__":
    main()
