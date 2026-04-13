from __future__ import annotations

import argparse
import subprocess
import tempfile
from pathlib import Path

APP_EXE_NAME = "sbom-viewer.exe"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Extract an MSI administratively and verify the packaged app files exist."
    )
    parser.add_argument("--msi-path", required=True)
    return parser


def admin_extract(msi_path: Path, destination: Path) -> None:
    subprocess.run(
        [
            "msiexec",
            "/a",
            str(msi_path),
            "/qn",
            f"TARGETDIR={destination}",
        ],
        check=True,
    )


def verify_extracted_layout(destination: Path) -> None:
    exe_paths = list(destination.rglob(APP_EXE_NAME))
    if not exe_paths:
        raise SystemExit(
            f"No {APP_EXE_NAME} found after administrative extraction: {destination}"
        )
    internal_dirs = [
        path for path in destination.rglob("_internal") if path.is_dir()
    ]
    if not internal_dirs:
        raise SystemExit(
            f"No _internal directory found after administrative extraction: {destination}"
        )


def main() -> None:
    args = build_parser().parse_args()
    msi_path = Path(args.msi_path).resolve()

    if not msi_path.is_file():
        raise SystemExit(f"MSI does not exist: {msi_path}")

    with tempfile.TemporaryDirectory(prefix="sbom-viewer-msi-") as tempdir:
        destination = Path(tempdir) / "extract"
        destination.mkdir()
        admin_extract(msi_path, destination)
        verify_extracted_layout(destination)

    print(f"MSI smoke test passed for {msi_path.stem}")


if __name__ == "__main__":
    main()
