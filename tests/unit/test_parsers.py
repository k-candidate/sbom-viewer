from pathlib import Path

import pytest

from app.models import SBOMModel
from app.parsers import PARSERS, detect_and_parse, get_supported_extensions
from app.parsers.base_parser import BaseSBOMParser
from app.parsers.spdx_parser import SPDXParser
from app.presentation import SBOMFormatter
from tests.support import FIXTURES_DIR, iter_sbom_fixtures


def test_every_fixture_is_detected_and_parsed() -> None:
    for fixture_path in iter_sbom_fixtures():
        parsed = detect_and_parse(str(fixture_path))

        assert "metadata" in parsed
        assert "components" in parsed
        assert "dependencies" in parsed
        assert isinstance(parsed["components"], list)
        assert isinstance(parsed["dependencies"], list)
        assert len(parsed["components"]) >= 1


def test_every_fixture_loads_into_model_rows() -> None:
    formatter = SBOMFormatter()

    for fixture_path in iter_sbom_fixtures():
        model = SBOMModel()
        model.load_from_parsed(detect_and_parse(str(fixture_path)))

        assert len(formatter.component_rows(model.get_components())) >= 1
        assert isinstance(
            formatter.dependency_rows(model.get_dependencies()), list
        )


def test_every_fixture_matches_normalized_schema_invariants() -> None:
    required_metadata_keys = {
        "name",
        "version",
        "creation_date",
        "supplier",
        "spec_version",
    }
    required_component_keys = {
        "name",
        "version",
        "licenses",
        "purl",
        "type",
        "supplier",
        "hashes",
        "description",
    }
    required_dependency_keys = {"from", "to", "type"}

    for fixture_path in iter_sbom_fixtures():
        parsed = detect_and_parse(str(fixture_path))

        assert set(parsed["metadata"]) >= required_metadata_keys
        assert isinstance(parsed["metadata"]["name"], str)
        assert isinstance(parsed["metadata"]["spec_version"], str)

        for component in parsed["components"]:
            assert set(component) >= required_component_keys
            assert isinstance(component["name"], str)
            assert isinstance(component["version"], str)
            assert isinstance(component["licenses"], list)
            assert all(isinstance(item, str) for item in component["licenses"])
            assert isinstance(component["purl"], str)
            assert isinstance(component["hashes"], dict)
            assert all(
                isinstance(key, str) and isinstance(value, str)
                for key, value in component["hashes"].items()
            )

        for dependency in parsed["dependencies"]:
            assert set(dependency) >= required_dependency_keys
            assert isinstance(dependency["from"], str)
            assert isinstance(dependency["to"], list)
            assert all(isinstance(item, str) for item in dependency["to"])
            assert isinstance(dependency["type"], str)


def test_legacy_swid_fixture_falls_back_cleanly() -> None:
    parsed = detect_and_parse(str(FIXTURES_DIR / "swid" / "swid2.xml"))

    assert parsed["metadata"]["name"] == "ProductABC"
    assert parsed["metadata"]["version"] == "4.00.0000"
    assert parsed["metadata"]["supplier"] == "Flexera"
    assert len(parsed["components"]) == 1
    assert "ProductABC_4.0.0" in parsed["components"][0]["purl"]


def test_cyclonedx_xml_component_descriptions_are_trimmed() -> None:
    parsed = detect_and_parse(str(FIXTURES_DIR / "cyclonedx" / "cdx-1.2.xml"))

    assert parsed["components"][0]["description"] == (
        "Node.js body parsing middleware"
    )


def test_cyclonedx_xml_and_json_dependency_counts_are_consistent() -> None:
    json_parsed = detect_and_parse(str(FIXTURES_DIR / "cyclonedx" / "cdx-1.3.json"))
    xml_parsed = detect_and_parse(str(FIXTURES_DIR / "cyclonedx" / "cdx-1.3.xml"))

    assert len(xml_parsed["dependencies"]) == len(json_parsed["dependencies"])


def test_cyclonedx_xml_spec_version_comes_from_schema_namespace() -> None:
    parsed = detect_and_parse(str(FIXTURES_DIR / "cyclonedx" / "cdx-1.5.xml"))

    assert parsed["metadata"]["spec_version"] == "1.5"


def test_supported_extensions_are_sorted_and_unique() -> None:
    extensions = get_supported_extensions()

    assert extensions == sorted(set(extensions))
    assert ".json" in extensions
    assert ".xml" in extensions
    assert ".spdx" in extensions
    assert ".swidtag" in extensions


def test_tag_value_parser_keeps_package_licenses_scoped() -> None:
    fixture_path = FIXTURES_DIR / "spdx" / "spdx-2.2.spdx"
    content = fixture_path.read_text(encoding="utf-8")

    parsed = SPDXParser().parse(
        str(fixture_path), fixture_path.read_bytes(), content
    )

    assert parsed["metadata"]["creation_date"] == "2021-08-26T01:46:00Z"
    assert len(parsed["components"]) == 1
    assert parsed["components"][0]["licenses"] == ["GPL-3.0-or-later"]
    assert (
        parsed["components"][0]["purl"]
        == "git+https://github.com/swinslow/spdx-examples.git#example1/content"
    )
    assert parsed["dependencies"] == []


def test_spdx_json_dependencies_are_resolved_to_component_names() -> None:
    parsed = detect_and_parse(str(FIXTURES_DIR / "spdx" / "spdx-2.2.json"))

    assert parsed["dependencies"] == [
        {
            "from": "junit",
            "to": ["hamcrest-core"],
            "type": "direct",
        },
        {
            "from": "App-BOM-ination",
            "to": ["commons-lang3"],
            "type": "direct",
        },
        {
            "from": "App-BOM-ination",
            "to": ["junit"],
            "type": "test",
        },
        {
            "from": "App-BOM-ination",
            "to": ["slf4j-api"],
            "type": "direct",
        },
    ]


def test_spdx_json_metadata_uses_creation_info_timestamp() -> None:
    parsed = detect_and_parse(str(FIXTURES_DIR / "spdx" / "spdx-2.3.json"))

    assert parsed["metadata"]["creation_date"] == "2024-11-18T10:22:12Z"


def test_spdx_v3_relationships_are_normalized_for_components() -> None:
    parsed = detect_and_parse(str(FIXTURES_DIR / "spdx" / "spdx-3.0.json"))

    assert parsed["dependencies"] == [
        {"from": "hello", "to": ["./src/hello.c"], "type": "contains"},
        {"from": "hello", "to": ["./build/hello"], "type": "contains"},
        {"from": "./src/Makefile", "to": ["./build/hello"], "type": "generates"},
        {"from": "./src/hello.c", "to": ["./build/hello"], "type": "generates"},
        {"from": "hello", "to": ["./src/Makefile"], "type": "contains"},
    ]


def test_spdx_noassertion_placeholders_are_treated_as_missing_values() -> None:
    parsed = detect_and_parse(str(FIXTURES_DIR / "spdx" / "spdx-2.3.json"))

    assert parsed["components"][0]["licenses"] == []
    assert parsed["components"][0]["purl"] == ""


def test_tagvalue_spdx_ignores_noassertion_license_entries() -> None:
    fixture_path = FIXTURES_DIR / "spdx" / "spdx-2.2.spdx"
    content = fixture_path.read_text(encoding="utf-8")

    parsed = SPDXParser().parse(
        str(fixture_path), fixture_path.read_bytes(), content
    )

    assert "NOASSERTION" not in parsed["components"][0]["licenses"]


def test_detect_and_parse_rejects_missing_files(tmp_path: Path) -> None:
    missing_file = tmp_path / "missing.json"

    with pytest.raises(ValueError, match="File not found"):
        detect_and_parse(str(missing_file))


def test_detect_and_parse_rejects_unknown_formats(tmp_path: Path) -> None:
    unknown_file = tmp_path / "unknown.txt"
    unknown_file.write_text("not an sbom", encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported SBOM format"):
        detect_and_parse(str(unknown_file))


def test_detect_and_parse_wraps_parser_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    class BrokenParser:
        def can_parse(self, file_path: str, content: bytes, content_str: str) -> bool:
            return True

        def parse(self, file_path: str, content: bytes, content_str: str) -> dict[str, object]:
            raise RuntimeError("bad parse")

        def get_extensions(self) -> list[str]:
            return [".broken"]

    monkeypatch.setattr("app.parsers.PARSERS", [BrokenParser()])
    fixture_path = FIXTURES_DIR / "spdx" / "spdx-2.2.json"

    with pytest.raises(ValueError, match="Parser BrokenParser failed: bad parse"):
        detect_and_parse(str(fixture_path))


class DummyParser(BaseSBOMParser):
    def can_parse(self, file_path: str, content: bytes, content_str: str) -> bool:
        return file_path.endswith(".dummy")

    def parse(self, file_path: str, content: bytes, content_str: str) -> dict[str, object]:
        return {"metadata": {}, "components": [], "dependencies": []}


def test_base_parser_normalization_helpers_trim_and_dedupe() -> None:
    parser = DummyParser()

    metadata = parser._normalize_metadata({"name": " demo ", "spec_version": " 1.0 "})
    component = parser._normalize_component(
        {
            "name": " pkg ",
            "version": " 1.2.3 ",
            "licenses": [" MIT ", "MIT", ""],
            "purl": " pkg:test/demo@1.2.3 ",
            "type": " library ",
            "supplier": " ACME ",
            "hashes": {" SHA-256 ": " abc ", "": "ignored", "SHA-1": ""},
            "description": " example ",
        }
    )

    assert metadata["name"] == "demo"
    assert metadata["spec_version"] == "1.0"
    assert component == {
        "name": "pkg",
        "version": "1.2.3",
        "licenses": ["MIT"],
        "purl": "pkg:test/demo@1.2.3",
        "type": "library",
        "supplier": "ACME",
        "hashes": {"SHA-256": "abc"},
        "description": "example",
    }

    dependencies = parser._normalize_dependencies(
        [
            {"from": " pkg ", "to": [" dep ", "dep", ""], "type": " direct "},
            {"from": "pkg", "to": ["dep"], "type": "direct"},
            {"from": "", "to": ["ignored"], "type": "direct"},
        ]
    )

    assert dependencies == [
        {"from": "pkg", "to": ["dep"], "type": "direct"}
    ]


def test_base_parser_default_extensions_is_empty() -> None:
    assert DummyParser().get_extensions() == []


def test_cyclonedx_invalid_json_raises_clean_error(tmp_path: Path) -> None:
    fixture_path = tmp_path / "broken.json"
    fixture_path.write_text('{"bomFormat": "CycloneDX",', encoding="utf-8")

    with pytest.raises(
        ValueError, match="Parser CycloneDXParser failed: Invalid CycloneDX JSON format"
    ):
        detect_and_parse(str(fixture_path))


def test_spdx_invalid_json_raises_clean_error(tmp_path: Path) -> None:
    fixture_path = tmp_path / "broken.json"
    fixture_path.write_text('{"spdxVersion": "SPDX-2.3",', encoding="utf-8")

    with pytest.raises(
        ValueError, match="Parser SPDXParser failed: Invalid SPDX JSON format"
    ):
        detect_and_parse(str(fixture_path))


def test_swid_invalid_xml_raises_clean_error(tmp_path: Path) -> None:
    fixture_path = tmp_path / "broken.xml"
    fixture_path.write_text(
        '<SoftwareIdentity xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd">',
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError, match="Parser SWIDParser failed: Invalid SWID XML format"
    ):
        detect_and_parse(str(fixture_path))
