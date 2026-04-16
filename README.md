# SBOM Viewer

Desktop GUI for viewing Software Bill of Materials (SBOM) files in multiple formats.

## Features
- Supported Formats:
  - SPDX
  - CycloneDX
  - SWID
- Auto-detect file format
- Tabbed views: Components, Dependencies, Metadata
- Search/filter in Components and Dependencies tabs
- Component details side panel
- Resizable columns & window

## Quick Start
```
# clone and cd
python main.py
```
Click on the "Open SBOM" button and select your file.

## Test files
Sample SBOMs in `tests/fixtures/sboms/`.

## Local packaging via Pyinstaller

Install dev dependencies first:

```bash
uv sync --locked --all-extras
```

Build the app:

```bash
uv run pyinstaller --noconfirm --clean sbom-viewer.spec
```

The built app will be created in:

- `dist/sbom-viewer/` on Linux and Windows
- `dist/SBOM Viewer.app` on macOS

Smoke-test the packaged app:

```bash
uv run python scripts/smoke_test_pyinstaller.py --app-dir dist/sbom-viewer
```

On Linux, run the smoke test under `xvfb` if needed:

```bash
xvfb-run -a uv run python scripts/smoke_test_pyinstaller.py --app-dir dist/sbom-viewer
```

Create a versioned archive:

```bash
uv run python scripts/package_pyinstaller_dist.py \
  --app-dir dist/sbom-viewer \
  --platform-id linux-x64 \
  --version 1.1.0 \
  --output-dir packaged
```
