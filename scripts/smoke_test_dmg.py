from __future__ import annotations

import argparse
import plistlib
import subprocess
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Mount a DMG and verify the expected app bundle layout."
    )
    parser.add_argument("--dmg-path", required=True)
    parser.add_argument("--app-name", default="SBOM Viewer.app")
    return parser


def attach_dmg(dmg_path: Path) -> Path:
    result = subprocess.run(
        [
            "hdiutil",
            "attach",
            str(dmg_path),
            "-nobrowse",
            "-readonly",
            "-plist",
        ],
        check=True,
        capture_output=True,
    )
    payload = plistlib.loads(result.stdout)
    for entity in payload.get("system-entities", []):
        mount_point = entity.get("mount-point")
        if mount_point:
            return Path(mount_point)
    raise SystemExit(f"Unable to determine mount point for {dmg_path}")


def detach_dmg(mount_point: Path) -> None:
    subprocess.run(["hdiutil", "detach", str(mount_point)], check=True)


def verify_mounted_layout(mount_point: Path, app_name: str) -> None:
    app_bundle = mount_point / app_name
    applications_link = mount_point / "Applications"
    executable = app_bundle / "Contents" / "MacOS" / "sbom-viewer"

    if not app_bundle.is_dir():
        raise SystemExit(f"App bundle missing from mounted DMG: {app_bundle}")
    if not executable.is_file():
        raise SystemExit(
            f"App executable missing from mounted DMG: {executable}"
        )
    if not applications_link.is_symlink():
        raise SystemExit(
            f"Applications shortcut missing or not a symlink: {applications_link}"
        )
    if applications_link.resolve() != Path("/Applications"):
        raise SystemExit(
            f"Applications shortcut does not point to /Applications: {applications_link.resolve()}"
        )


def main() -> None:
    args = build_parser().parse_args()
    dmg_path = Path(args.dmg_path).resolve()

    if not dmg_path.is_file():
        raise SystemExit(f"DMG does not exist: {dmg_path}")

    mount_point = attach_dmg(dmg_path)
    try:
        verify_mounted_layout(mount_point, args.app_name)
    finally:
        detach_dmg(mount_point)

    print(f"DMG smoke test passed for {dmg_path.stem}")


if __name__ == "__main__":
    main()
