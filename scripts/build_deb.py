from __future__ import annotations

import argparse
import shutil
import stat
import subprocess
import tarfile
import tempfile
from pathlib import Path

PRODUCT_NAME = "SBOM Viewer"
MANUFACTURER = "k-candidate"
APP_EXE_NAME = "sbom-viewer"
ICON_PATH = Path("assets/logo/sbom-viewer.png").resolve()
MAINTAINER = "k-candidate <invalid@invalid.invalid>"
HOMEPAGE = "https://github.com/k-candidate/sbom-viewer"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create a Debian package from a PyInstaller app archive."
    )
    parser.add_argument("--app-archive", required=True)
    parser.add_argument("--output-path", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--platform-id", required=True)
    return parser


def extract_archive(archive_path: Path, destination: Path) -> None:
    shutil.unpack_archive(str(archive_path), str(destination))


def find_app_dir(root: Path) -> Path:
    exe_paths = sorted(
        path for path in root.rglob(APP_EXE_NAME) if path.is_file()
    )
    if not exe_paths:
        raise SystemExit(
            f"No {APP_EXE_NAME} found in extracted archive: {root}"
        )
    if len(exe_paths) > 1:
        raise SystemExit(
            f"Expected exactly one {APP_EXE_NAME} in extracted archive, found {len(exe_paths)}"
        )
    return exe_paths[0].parent


def installer_arch(platform_id: str) -> str:
    if platform_id == "linux-x64":
        return "amd64"
    if platform_id == "linux-arm64":
        return "arm64"
    raise SystemExit(f"Unsupported Linux platform id: {platform_id}")


def generate_control_file(
    version: str,
    arch: str,
) -> str:
    return f"""\
Package: sbom-viewer
Version: {version}
Architecture: {arch}
Maintainer: {MAINTAINER}
Homepage: {HOMEPAGE}
Description: Desktop GUI for viewing Software Bill of Materials (SBOM) files
 Supports SPDX, CycloneDX, and SWID formats with auto-detection,
 tabbed views, search/filter capabilities, and component details panel.
"""


def generate_desktop_file() -> str:
    return """\
[Desktop Entry]
Type=Application
Name=SBOM Viewer
Comment=View Software Bill of Materials files
Exec=/usr/bin/sbom-viewer
Icon=sbom-viewer
Categories=Utility;
"""


def generate_postinst_script() -> str:
    return """\
#!/bin/bash
set -e

# Create symlink for the executable
ln -sf /opt/sbom-viewer/sbom-viewer /usr/bin/sbom-viewer

# Update desktop database
if command -v update-desktop-database &> /dev/null; then
    update-desktop-database /usr/share/applications || true
fi

# Update icon cache
if command -v gtk-update-icon-cache &> /dev/null; then
    gtk-update-icon-cache /usr/share/icons/hicolor || true
fi

exit 0
"""


def generate_prerm_script() -> str:
    return """\
#!/bin/bash
set -e

# Remove symlink
rm -f /usr/bin/sbom-viewer

exit 0
"""


def build_deb(
    app_dir: Path,
    version: str,
    output_path: Path,
    arch: str,
) -> None:
    """Build a Debian package from the app directory."""
    with tempfile.TemporaryDirectory(prefix="sbom-viewer-deb-") as tempdir:
        temp_path = Path(tempdir)
        deb_path = temp_path / "deb"
        deb_path.mkdir()

        # Create directory structure
        debian_dir = deb_path / "DEBIAN"
        debian_dir.mkdir()

        opt_dir = deb_path / "opt" / "sbom-viewer"
        opt_dir.mkdir(parents=True)

        apps_dir = deb_path / "usr" / "share" / "applications"
        apps_dir.mkdir(parents=True)

        icons_dir = (
            deb_path
            / "usr"
            / "share"
            / "icons"
            / "hicolor"
            / "256x256"
            / "apps"
        )
        icons_dir.mkdir(parents=True)

        # Copy app files
        for item in app_dir.iterdir():
            dest = opt_dir / item.name
            if item.is_dir():
                shutil.copytree(item, dest)
            else:
                shutil.copy2(item, dest)

        # Make executable permissions preserved
        exe_path = opt_dir / APP_EXE_NAME
        if exe_path.exists():
            exe_path.chmod(
                exe_path.stat().st_mode
                | stat.S_IXUSR
                | stat.S_IXGRP
                | stat.S_IXOTH
            )

        # Write control file
        (debian_dir / "control").write_text(
            generate_control_file(version, arch),
            encoding="utf-8",
        )

        # Write postinst script
        postinst_path = debian_dir / "postinst"
        postinst_path.write_text(
            generate_postinst_script(),
            encoding="utf-8",
        )
        postinst_path.chmod(0o755)

        # Write prerm script
        prerm_path = debian_dir / "prerm"
        prerm_path.write_text(
            generate_prerm_script(),
            encoding="utf-8",
        )
        prerm_path.chmod(0o755)

        # Write .desktop file
        (apps_dir / "sbom-viewer.desktop").write_text(
            generate_desktop_file(),
            encoding="utf-8",
        )

        # Copy icon
        if not ICON_PATH.is_file():
            raise SystemExit(f"Icon file does not exist: {ICON_PATH}")
        shutil.copy2(ICON_PATH, icons_dir / "sbom-viewer.png")

        # Create control.tar.gz
        control_tar_gz = temp_path / "control.tar.gz"
        with tarfile.open(control_tar_gz, "w:gz") as tar:
            tar.add(
                debian_dir,
                arcname=".",
                filter=lambda ti: _strip_leading_slash(ti),
            )

        # Create data.tar.gz (filesystem tree)
        data_tar_gz = temp_path / "data.tar.gz"
        with tarfile.open(data_tar_gz, "w:gz") as tar:
            for subdir in ["opt", "usr"]:
                subdir_path = deb_path / subdir
                if subdir_path.exists():
                    tar.add(
                        subdir_path,
                        arcname=f"./{subdir}",
                        filter=lambda ti: _strip_leading_slash(ti),
                    )

        # Create debian-binary file (version indicator)
        debian_binary = temp_path / "debian-binary"
        debian_binary.write_text("2.0\n")

        # Create final DEB using ar
        output_path.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "ar",
                "r",
                str(output_path),
                str(debian_binary),
                str(control_tar_gz),
                str(data_tar_gz),
            ],
            check=True,
        )


def _strip_leading_slash(tarinfo):
    """Remove leading slash from tar entry names."""
    if tarinfo.name.startswith("./"):
        return tarinfo
    if tarinfo.name.startswith("/"):
        tarinfo.name = tarinfo.name.lstrip("/")
    return tarinfo


def main() -> None:
    args = build_parser().parse_args()
    archive_path = Path(args.app_archive).resolve()
    output_path = Path(args.output_path).resolve()

    if not archive_path.is_file():
        raise SystemExit(f"App archive does not exist: {archive_path}")
    if not ICON_PATH.is_file():
        raise SystemExit(f"Icon file does not exist: {ICON_PATH}")

    arch = installer_arch(args.platform_id)

    with tempfile.TemporaryDirectory(
        prefix="sbom-viewer-deb-extract-"
    ) as tempdir:
        temp_path = Path(tempdir)
        extract_dir = temp_path / "extracted"
        extract_dir.mkdir()
        extract_archive(archive_path, extract_dir)
        app_dir = find_app_dir(extract_dir)
        build_deb(app_dir, args.version, output_path, arch)

    print(output_path.name)


if __name__ == "__main__":
    main()
