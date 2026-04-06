from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Archive a PyInstaller onedir output with a versioned name."
    )
    parser.add_argument("--app-dir", required=True)
    parser.add_argument("--platform-id", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output-dir", required=True)
    return parser


def archive_format(platform_id: str) -> str:
    if platform_id.startswith("linux-"):
        return "gztar"
    return "zip"


def extension_for(fmt: str) -> str:
    if fmt == "gztar":
        return ".tar.gz"
    return ".zip"


def archive_with_ditto(app_dir: Path, archive_path: Path) -> None:
    subprocess.run(
        [
            "ditto",
            "-c",
            "-k",
            "--sequesterRsrc",
            "--keepParent",
            str(app_dir),
            str(archive_path),
        ],
        check=True,
    )


def main() -> None:
    args = build_parser().parse_args()

    app_dir = Path(args.app_dir).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if not app_dir.is_dir():
        raise SystemExit(f"App directory does not exist: {app_dir}")

    fmt = archive_format(args.platform_id)
    base_name = output_dir / f"sbom-viewer-{args.version}-{args.platform_id}"
    if args.platform_id.startswith("macos-"):
        archive_path = Path(str(base_name) + extension_for(fmt))
        archive_with_ditto(app_dir, archive_path)
    else:
        archive_path = Path(
            shutil.make_archive(
                str(base_name),
                fmt,
                root_dir=app_dir.parent,
                base_dir=app_dir.name,
            )
        )
    print(Path(archive_path).name)
    print(base_name.name + extension_for(fmt))


if __name__ == "__main__":
    main()
