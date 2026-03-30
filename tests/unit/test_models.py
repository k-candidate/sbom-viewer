from app.models import SBOMModel
from app.parsers import detect_and_parse
from app.presentation import SBOMFormatter
from tests.support import FIXTURES_DIR


def build_model() -> SBOMModel:
    model = SBOMModel()
    model.load_from_parsed(
        {
            "metadata": {"name": "demo"},
            "components": [
                {
                    "name": "Requests",
                    "version": "2.31.0",
                    "licenses": ["Apache-2.0"],
                    "purl": "pkg:pypi/requests@2.31.0",
                    "type": "library",
                    "supplier": "PSF",
                    "hashes": {"SHA-256": "abc123"},
                    "description": "HTTP client",
                },
                {
                    "name": "Flask",
                    "version": "3.0.1",
                    "licenses": ["BSD-3-Clause"],
                    "purl": "pkg:pypi/flask@3.0.1",
                    "type": "library",
                    "supplier": "Pallets",
                    "hashes": {},
                    "description": "",
                },
            ],
            "dependencies": [
                {"from": "Requests", "to": ["urllib3"], "type": "direct"}
            ],
        }
    )
    return model


def build_formatter() -> SBOMFormatter:
    return SBOMFormatter()


def test_component_filter_matches_multiple_fields() -> None:
    model = build_model()

    assert len(model.get_components("requests")) == 1
    assert len(model.get_components("2.31")) == 1
    assert len(model.get_components("apache")) == 1
    assert len(model.get_components("pkg:pypi/flask")) == 1
    assert len(model.get_components("   ")) == 2


def test_dependency_filter_matches_source_and_targets() -> None:
    model = build_model()

    assert len(model.get_dependencies("requests")) == 1
    assert len(model.get_dependencies("urllib3")) == 1
    assert len(model.get_dependencies("missing")) == 0


def test_component_details_lookup_is_case_insensitive() -> None:
    model = build_model()

    by_name = model.get_component_details("requests")
    by_suffix = model.get_component_details("requests@2.31.0")
    by_purl = model.get_component_by_purl("PKG:PYPI/REQUESTS@2.31.0")

    assert by_name is not None
    assert by_suffix is not None
    assert by_purl is not None
    assert by_name["name"] == "Requests"


def test_component_rows_match_gui_shape() -> None:
    model = build_model()
    formatter = build_formatter()

    assert formatter.component_rows(model.get_components()) == [
        ("Requests", "2.31.0", "Apache-2.0", "pkg:pypi/requests@2.31.0"),
        ("Flask", "3.0.1", "BSD-3-Clause", "pkg:pypi/flask@3.0.1"),
    ]


def test_dependency_rows_match_gui_shape() -> None:
    model = build_model()
    formatter = build_formatter()

    assert formatter.dependency_rows(model.get_dependencies()) == [
        ("Requests", "urllib3", "direct")
    ]


def test_format_component_details_uses_stable_order() -> None:
    model = build_model()
    formatter = build_formatter()

    assert formatter.component_details(
        model.get_component_details("requests")
    ) == "\n".join(
        [
            "name: Requests",
            "version: 2.31.0",
            "licenses: Apache-2.0",
            "purl: pkg:pypi/requests@2.31.0",
            "type: library",
            "supplier: PSF",
            "hashes:",
            "  SHA-256: abc123",
            "description: HTTP client",
        ]
    )


def test_format_component_details_handles_missing_component() -> None:
    formatter = build_formatter()

    assert formatter.component_details(None) == "Component not found."


def test_fixture_backed_component_search_matches_real_rows() -> None:
    model = SBOMModel()
    formatter = build_formatter()
    fixture_path = FIXTURES_DIR / "cyclonedx" / "cdx-1.5.json"
    model.load_from_parsed(detect_and_parse(str(fixture_path)))

    assert formatter.component_rows(model.get_components("MIT")) == [
        ("six", "1.16.0", "MIT", "pkg:pypi/six@1.16.0")
    ]
    assert formatter.component_rows(model.get_components("1.16.0")) == [
        ("six", "1.16.0", "MIT", "pkg:pypi/six@1.16.0")
    ]


def test_fixture_backed_dependency_search_matches_real_rows() -> None:
    model = SBOMModel()
    formatter = build_formatter()
    fixture_path = FIXTURES_DIR / "cyclonedx" / "cdx-1.5.json"
    model.load_from_parsed(detect_and_parse(str(fixture_path)))

    assert formatter.dependency_rows(model.get_dependencies("1.16.0")) == [
        ("root-component", "six==1.16.0", "direct"),
        ("six==1.16.0", "None", "direct"),
    ]


def test_fixture_backed_component_search_handles_other_formats() -> None:
    model = SBOMModel()
    formatter = build_formatter()

    spdx_fixture = FIXTURES_DIR / "spdx" / "spdx-2.2.spdx"
    model.load_from_parsed(detect_and_parse(str(spdx_fixture)))
    assert formatter.component_rows(
        model.get_components("GPL-3.0-or-later")
    ) == [
        (
            "hello",
            "",
            "GPL-3.0-or-later",
            "git+https://github.com/swinslow/spdx-examples.git#example1/content",
        )
    ]

    swid_fixture = FIXTURES_DIR / "swid" / "swid.xml"
    model.load_from_parsed(detect_and_parse(str(swid_fixture)))
    assert formatter.component_rows(model.get_components("Cisco")) == [
        ("Snort", "3.0", "", "Cisco-Snort-3.0")
    ]
