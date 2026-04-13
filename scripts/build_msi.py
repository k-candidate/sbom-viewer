from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import tempfile
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

WIX_NAMESPACE = "http://wixtoolset.org/schemas/v4/wxs"
ET.register_namespace("", WIX_NAMESPACE)

PRODUCT_NAME = "SBOM Viewer"
MANUFACTURER = "k-candidate"
UPGRADE_CODE = "57D5FE50-0CD0-45E7-B73D-5A8A136F4B78"
APP_EXE_NAME = "sbom-viewer.exe"
ICON_PATH = Path("assets/icons/sbom-viewer.ico").resolve()
GUID_NAMESPACE = uuid.UUID("9ef7137c-5b0a-4574-9f44-0f70720b5f6c")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create a Windows MSI from a PyInstaller app archive."
    )
    parser.add_argument("--app-archive", required=True)
    parser.add_argument("--output-path", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--platform-id", required=True)
    return parser


def extract_archive(archive_path: Path, destination: Path) -> None:
    shutil.unpack_archive(str(archive_path), str(destination))


def find_app_dir(root: Path) -> Path:
    exe_paths = sorted(root.rglob(APP_EXE_NAME))
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
    if platform_id == "windows-x64":
        return "x64"
    if platform_id == "windows-arm64":
        return "arm64"
    raise SystemExit(f"Unsupported Windows platform id: {platform_id}")


def safe_id(prefix: str, value: str) -> str:
    digest = hashlib.sha1(value.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}_{digest}"


def component_guid(rel_path: Path) -> str:
    return str(uuid.uuid5(GUID_NAMESPACE, rel_path.as_posix())).upper()


def wix_name() -> str:
    return f"{{{WIX_NAMESPACE}}}"


def build_wxs(app_dir: Path, version: str, output_path: Path) -> None:
    ns = wix_name()
    wix = ET.Element(f"{ns}Wix")

    package = ET.SubElement(
        wix,
        f"{ns}Package",
        {
            "Name": PRODUCT_NAME,
            "Manufacturer": MANUFACTURER,
            "Version": version,
            "UpgradeCode": UPGRADE_CODE,
            "Scope": "perMachine",
            "Language": "1033",
            "InstallerVersion": "500",
        },
    )
    ET.SubElement(
        package,
        f"{ns}MajorUpgrade",
        {
            "DowngradeErrorMessage": "A newer version of SBOM Viewer is already installed."
        },
    )
    ET.SubElement(package, f"{ns}MediaTemplate", {"EmbedCab": "yes"})
    ET.SubElement(
        package,
        f"{ns}Icon",
        {"Id": "AppIcon", "SourceFile": str(ICON_PATH)},
    )
    ET.SubElement(
        package,
        f"{ns}Property",
        {"Id": "ARPPRODUCTICON", "Value": "AppIcon"},
    )

    standard_dir = ET.SubElement(
        package, f"{ns}StandardDirectory", {"Id": "ProgramFiles6432Folder"}
    )
    vendor_dir = ET.SubElement(
        standard_dir,
        f"{ns}Directory",
        {"Id": "ManufacturerFolder", "Name": MANUFACTURER},
    )
    install_dir = ET.SubElement(
        vendor_dir,
        f"{ns}Directory",
        {"Id": "INSTALLFOLDER", "Name": PRODUCT_NAME},
    )

    directory_elements: dict[Path, ET.Element] = {Path("."): install_dir}
    component_ids: list[str] = []

    for file_path in sorted(
        path for path in app_dir.rglob("*") if path.is_file()
    ):
        rel_path = file_path.relative_to(app_dir)
        parent_rel = rel_path.parent

        current = Path(".")
        for part in parent_rel.parts:
            current /= part
            if current not in directory_elements:
                parent_element = directory_elements[current.parent]
                directory_elements[current] = ET.SubElement(
                    parent_element,
                    f"{ns}Directory",
                    {"Id": safe_id("dir", current.as_posix()), "Name": part},
                )

        component_id = safe_id("cmp", rel_path.as_posix())
        component_ids.append(component_id)
        component = ET.SubElement(
            directory_elements[parent_rel],
            f"{ns}Component",
            {"Id": component_id, "Guid": component_guid(rel_path)},
        )
        ET.SubElement(
            component,
            f"{ns}File",
            {
                "Id": safe_id("fil", rel_path.as_posix()),
                "Source": str(file_path),
                "KeyPath": "yes",
            },
        )

    feature = ET.SubElement(
        package,
        f"{ns}Feature",
        {"Id": "MainFeature", "Title": PRODUCT_NAME, "Level": "1"},
    )
    component_fragment = ET.SubElement(wix, f"{ns}Fragment")
    component_group = ET.SubElement(
        component_fragment, f"{ns}ComponentGroup", {"Id": "ProductComponents"}
    )
    for component_id in component_ids:
        ET.SubElement(
            component_group, f"{ns}ComponentRef", {"Id": component_id}
        )
    ET.SubElement(
        feature, f"{ns}ComponentGroupRef", {"Id": "ProductComponents"}
    )

    ET.indent(wix, space="  ")
    ET.ElementTree(wix).write(
        output_path, encoding="utf-8", xml_declaration=True
    )


def build_msi(wxs_path: Path, output_path: Path, arch: str) -> None:
    subprocess.run(
        [
            "wix",
            "build",
            str(wxs_path),
            "-arch",
            arch,
            "-o",
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
    if not ICON_PATH.is_file():
        raise SystemExit(f"Installer icon does not exist: {ICON_PATH}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    arch = installer_arch(args.platform_id)

    with tempfile.TemporaryDirectory(prefix="sbom-viewer-msi-") as tempdir:
        temp_path = Path(tempdir)
        extract_dir = temp_path / "extracted"
        extract_dir.mkdir()
        extract_archive(archive_path, extract_dir)
        app_dir = find_app_dir(extract_dir)
        wxs_path = temp_path / "sbom-viewer.wxs"
        build_wxs(app_dir, args.version, wxs_path)
        build_msi(wxs_path, output_path, arch)

    print(output_path.name)


if __name__ == "__main__":
    main()
