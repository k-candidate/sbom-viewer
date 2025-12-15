import tempfile
from pathlib import Path

from tests.integration.generate_expected_gui_snapshots import build_gui_snapshot
from tests.support import (
    FIXTURES_DIR,
    expected_gui_snapshot_path,
    fixture_relative_path,
    iter_sbom_fixtures,
)


def test_expected_snapshot_paths_are_unique() -> None:
    paths = [expected_gui_snapshot_path(path) for path in iter_sbom_fixtures()]

    assert len(paths) == len(set(paths))


def test_generator_snapshot_payload_has_expected_shape() -> None:
    fixture_path = next(path for path in iter_sbom_fixtures() if path.name == "cdx-1.5.json")
    snapshot = build_gui_snapshot(fixture_path)

    assert snapshot["fixture"] == str(fixture_relative_path(fixture_path))
    assert set(snapshot) == {
        "fixture",
        "metadata",
        "component_rows",
        "dependency_rows",
    }
    assert isinstance(snapshot["metadata"], dict)
    assert isinstance(snapshot["component_rows"], list)
    assert isinstance(snapshot["dependency_rows"], list)


def test_expected_snapshot_path_preserves_original_extension() -> None:
    fixture_path = FIXTURES_DIR / "cyclonedx" / "cdx-1.5.xml"
    expected_path = expected_gui_snapshot_path(fixture_path)

    assert expected_path.name == "cdx-1.5.xml.expected.json"
