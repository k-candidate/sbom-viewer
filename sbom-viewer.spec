# -*- mode: python ; coding: utf-8 -*-

from __future__ import annotations

import sys
from pathlib import Path
import tomllib
import _tkinter


PROJECT_ROOT = Path.cwd()
PYPROJECT = PROJECT_ROOT / "pyproject.toml"
PROJECT = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
APP_NAME = PROJECT["name"]
DISPLAY_NAME = "SBOM Viewer"
APP_VERSION = PROJECT["version"]
BUNDLE_IDENTIFIER = "io.github.k-candidate.sbom-viewer"
IS_MACOS = sys.platform == "darwin"
IS_WINDOWS = sys.platform == "win32"
WINDOWS_ICON = str(PROJECT_ROOT / "assets" / "icons" / "sbom-viewer.ico")
MACOS_ICON = str(PROJECT_ROOT / "assets" / "icons" / "sbom-viewer.icns")
APP_ICON = WINDOWS_ICON if IS_WINDOWS else None
PYTHON_BUILD_ROOT = Path(_tkinter.__file__).resolve().parents[3]
TK_RUNTIME_LIBRARIES = [
    (str(path), ".")
    for path in sorted(PYTHON_BUILD_ROOT.joinpath("lib").glob("libt*"))
]

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=TK_RUNTIME_LIBRARIES,
    datas=[
        (
            str(PROJECT_ROOT / "assets" / "logo" / "sbom-viewer.png"),
            "assets/logo",
        ),
    ],
    hiddenimports=[
        "tkinter",
        "tkinter.ttk",
        "tkinter.filedialog",
        "tkinter.messagebox",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name=APP_NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=APP_ICON,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name=APP_NAME,
)

if IS_MACOS:
    app = BUNDLE(
        coll,
        name=f"{DISPLAY_NAME}.app",
        icon=MACOS_ICON,
        bundle_identifier=BUNDLE_IDENTIFIER,
        version=APP_VERSION,
        info_plist={
            "CFBundleName": DISPLAY_NAME,
            "CFBundleDisplayName": DISPLAY_NAME,
            "CFBundleExecutable": APP_NAME,
            "CFBundleShortVersionString": APP_VERSION,
            "CFBundleVersion": APP_VERSION,
            "NSHighResolutionCapable": True,
        },
    )
