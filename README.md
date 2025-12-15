# sbom-viewer

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