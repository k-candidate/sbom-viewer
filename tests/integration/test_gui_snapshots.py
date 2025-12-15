from pathlib import Path

from app.models import SBOMModel
from app.parsers import detect_and_parse
from app.presentation import SBOMFormatter
from tests.support import (
    FIXTURES_DIR,
    expected_gui_snapshot_path,
    fixture_relative_path,
    load_json,
)


def build_gui_snapshot(fixture_path) -> dict[str, object]:
    model = SBOMModel()
    formatter = SBOMFormatter()
    model.load_from_parsed(detect_and_parse(str(fixture_path)))
    return {
        "fixture": str(fixture_relative_path(fixture_path)),
        "metadata": model.get_metadata(),
        "component_rows": [
            list(row) for row in formatter.component_rows(model.get_components())
        ],
        "dependency_rows": [
            list(row)
            for row in formatter.dependency_rows(model.get_dependencies())
        ],
    }


def test_gui_snapshot_matches_expected(sbom_fixture_path) -> None:
    expected_path = expected_gui_snapshot_path(sbom_fixture_path)
    assert expected_path.exists(), f"Missing expected snapshot: {expected_path}"

    actual_snapshot = build_gui_snapshot(sbom_fixture_path)
    expected_snapshot = load_json(expected_path)

    assert actual_snapshot == expected_snapshot


def test_selected_snapshots_have_semantic_expectations() -> None:
    cases = [
        (
            Path("cyclonedx/cdx-1.5.json"),
            {
                "metadata_name": "editable-self",
                "component_count": 1,
                "dependency_count": 2,
                "component_row": ["six", "1.16.0", "MIT", "pkg:pypi/six@1.16.0"],
                "dependency_row": ["root-component", "six==1.16.0", "direct"],
            },
        ),
        (
            Path("spdx/spdx-2.2.spdx"),
            {
                "metadata_name": "hello",
                "component_count": 1,
                "dependency_count": 0,
                "component_row": [
                    "hello",
                    "",
                    "GPL-3.0-or-later",
                    "git+https://github.com/swinslow/spdx-examples.git#example1/content",
                ],
            },
        ),
        (
            Path("spdx/spdx-2.2.json"),
            {
                "metadata_name": "SpdxDoc for App-BOM-ination",
                "component_count": 7,
                "dependency_count": 4,
                "component_row": [
                    "App-BOM-ination",
                    "1.0",
                    "(LicenseRef-1 AND Apache-2.0)",
                    "https://github.com/act-project/App-BOM-ination/archive/refs/tags/1.0.zip",
                ],
                "dependency_row": [
                    "App-BOM-ination",
                    "commons-lang3",
                    "direct",
                ],
            },
        ),
        (
            Path("swid/swid.xml"),
            {
                "metadata_name": "Snort",
                "component_count": 1,
                "dependency_count": 0,
                "component_row": ["Snort", "3.0", "", "Cisco-Snort-3.0"],
            },
        ),
    ]

    for relative_path, expected in cases:
        snapshot = load_json(expected_gui_snapshot_path(FIXTURES_DIR / relative_path))

        assert snapshot["metadata"]["name"] == expected["metadata_name"]
        assert len(snapshot["component_rows"]) == expected["component_count"]
        assert len(snapshot["dependency_rows"]) == expected["dependency_count"]
        assert expected["component_row"] in snapshot["component_rows"]
        if "dependency_row" in expected:
            assert expected["dependency_row"] in snapshot["dependency_rows"]
