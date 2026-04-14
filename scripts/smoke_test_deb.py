from __future__ import annotations

import argparse
import subprocess
import tarfile
import tempfile
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Smoke test a Debian package."
    )
    parser.add_argument(
        "--deb-path", required=True, help="Path to the .deb file"
    )
    return parser


def verify_deb_integrity(deb_path: Path) -> None:
    """Verify the DEB file has valid structure."""
    if not deb_path.suffix == ".deb":
        raise SystemExit(f"File not a .deb: {deb_path}")

    if not deb_path.is_file():
        raise SystemExit(f"DEB file does not exist: {deb_path}")

    # DEB files are ar archives, which are also readable as tar
    # Try to extract and inspect contents
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Extract DEB (ar archive format)
            subprocess.run(
                ["ar", "x", str(deb_path)],
                cwd=str(temp_path),
                check=True,
                capture_output=True,
            )

            # Check for required files in ar archive
            contents = list(temp_path.iterdir())
            names = {item.name for item in contents}

            required = {"control.tar.gz", "data.tar.gz", "debian-binary"}
            missing = required - names
            if missing:
                raise SystemExit(
                    f"DEB archive missing required files: {missing}"
                )

            # Extract control.tar.gz and verify metadata
            control_tar = temp_path / "control.tar.gz"
            with tarfile.open(control_tar, "r:gz") as tar:
                members = tar.getnames()
                required_control = {"./control", "./postinst", "./prerm"}
                present = set(members)
                missing_control = required_control - present
                if missing_control:
                    raise SystemExit(
                        f"Missing control files: {missing_control}"
                    )

                # Verify control file has required fields
                control_file = tar.extractfile("./control")
                if not control_file:
                    raise SystemExit("Cannot read control file")

                control_content = control_file.read().decode("utf-8")
                required_fields = {
                    "Package:",
                    "Version:",
                    "Architecture:",
                    "Maintainer:",
                    "Description:",
                }
                for field in required_fields:
                    if field not in control_content:
                        raise SystemExit(
                            f"Control file missing field: {field}"
                        )

            # Extract data.tar.gz and verify files
            data_tar = temp_path / "data.tar.gz"
            with tarfile.open(data_tar, "r:gz") as tar:
                members = tar.getnames()
                required_data = {
                    "./opt/sbom-viewer/sbom-viewer",
                    "./usr/share/applications/sbom-viewer.desktop",
                    "./usr/share/icons/hicolor/256x256/apps/sbom-viewer.png",
                }
                present_data = set(members)
                missing_data = required_data - present_data
                if missing_data:
                    raise SystemExit(f"Missing data files: {missing_data}")

                # Verify .desktop file is valid
                desktop_file = tar.extractfile(
                    "./usr/share/applications/sbom-viewer.desktop"
                )
                if not desktop_file:
                    raise SystemExit("Cannot read .desktop file")

                desktop_content = desktop_file.read().decode("utf-8")
                required_desktop = {
                    "[Desktop Entry]",
                    "Name=SBOM Viewer",
                    "Exec=/usr/bin/sbom-viewer",
                }
                for entry in required_desktop:
                    if entry not in desktop_content:
                        raise SystemExit(f".desktop file missing: {entry}")

    except subprocess.CalledProcessError as e:
        raise SystemExit(
            f"Failed to extract DEB: {e.stderr.decode('utf-8', errors='replace')}"
        ) from e


def main() -> None:
    args = build_parser().parse_args()
    deb_path = Path(args.deb_path).resolve()

    print(f"Verifying DEB package: {deb_path.name}")
    verify_deb_integrity(deb_path)
    print("✓ DEB package verification passed")


if __name__ == "__main__":
    main()
