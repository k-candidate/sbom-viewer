from dataclasses import dataclass, field
from typing import Any

import pytest

from app.models import SBOMModel
from app.parsers import detect_and_parse
from app.presentation import ComponentRow, DependencyRow
from app.presenter import SBOMPresenter
from tests.support import FIXTURES_DIR


@dataclass
class FakeView:
    metadata: dict[str, Any] | None = None
    component_rows: list[ComponentRow] = field(default_factory=list)
    dependency_rows: list[DependencyRow] = field(default_factory=list)
    detail_text: str = ""
    statuses: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    cleared: bool = False

    def set_metadata(self, metadata: dict[str, Any]) -> None:
        self.metadata = metadata

    def set_component_rows(self, rows: list[ComponentRow]) -> None:
        self.component_rows = rows

    def set_dependency_rows(self, rows: list[DependencyRow]) -> None:
        self.dependency_rows = rows

    def show_component_details(self, details: str) -> None:
        self.detail_text = details

    def show_status(self, message: str) -> None:
        self.statuses.append(message)

    def show_error(self, message: str) -> None:
        self.errors.append(message)

    def clear_all(self) -> None:
        self.cleared = True


def sample_parsed_data() -> dict[str, Any]:
    return {
        "metadata": {"name": "demo"},
        "components": [
            {
                "name": "Requests",
                "version": "2.31.0",
                "licenses": ["Apache-2.0"],
                "purl": "pkg:pypi/requests@2.31.0",
                "type": "library",
                "supplier": "PSF",
                "hashes": {},
                "description": "HTTP client",
            }
        ],
        "dependencies": [
            {"from": "Requests", "to": ["urllib3"], "type": "direct"}
        ],
    }


def test_load_parsed_data_updates_view() -> None:
    presenter = SBOMPresenter()
    view = FakeView()
    presenter.attach_view(view)

    presenter.load_parsed_data(sample_parsed_data())

    assert view.metadata == {"name": "demo"}
    assert view.component_rows == [
        ("Requests", "2.31.0", "Apache-2.0", "pkg:pypi/requests@2.31.0")
    ]
    assert view.dependency_rows == [("Requests", "urllib3", "direct")]


def test_filter_methods_use_gui_rows() -> None:
    presenter = SBOMPresenter()
    view = FakeView()
    presenter.attach_view(view)
    presenter.load_parsed_data(sample_parsed_data())

    presenter.filter_components("requests")
    presenter.filter_dependencies("urllib3")

    assert view.component_rows == [
        ("Requests", "2.31.0", "Apache-2.0", "pkg:pypi/requests@2.31.0")
    ]
    assert view.dependency_rows == [("Requests", "urllib3", "direct")]


def test_show_component_details_uses_model_formatter() -> None:
    presenter = SBOMPresenter()
    view = FakeView()
    presenter.attach_view(view)
    presenter.load_parsed_data(sample_parsed_data())

    presenter.show_component_details("requests")

    assert "name: Requests" in view.detail_text
    assert "purl: pkg:pypi/requests@2.31.0" in view.detail_text


def test_clear_view_resets_model_and_view() -> None:
    presenter = SBOMPresenter(model=SBOMModel())
    view = FakeView()
    presenter.attach_view(view)
    presenter.load_parsed_data(sample_parsed_data())

    presenter.clear_view()

    assert view.cleared is True
    assert presenter.model.get_components() == []


def test_load_sbom_reports_errors() -> None:
    def failing_loader(_: str) -> dict[str, Any]:
        raise ValueError("boom")

    presenter = SBOMPresenter(parser_loader=failing_loader)
    view = FakeView()
    presenter.attach_view(view)

    presenter.load_sbom("broken.json")

    assert view.errors == ["Failed to load SBOM: boom"]
    assert view.statuses[-1] == "Load failed"


def test_load_sbom_success_tracks_current_file_and_status() -> None:
    presenter = SBOMPresenter(parser_loader=lambda _: sample_parsed_data())
    view = FakeView()
    presenter.attach_view(view)

    presenter.load_sbom("/tmp/example.json")

    assert presenter.current_file_path == "/tmp/example.json"
    assert view.statuses[0] == "Loading example.json..."
    assert view.statuses[-1] == "Loaded SBOM: 1 components"


def test_reload_file_reuses_current_file_path() -> None:
    seen_paths: list[str] = []

    def loader(path: str) -> dict[str, Any]:
        seen_paths.append(path)
        return sample_parsed_data()

    presenter = SBOMPresenter(parser_loader=loader)
    view = FakeView()
    presenter.attach_view(view)
    presenter.current_file_path = "/tmp/reload.json"

    presenter.reload_file()

    assert seen_paths == ["/tmp/reload.json"]


def test_reload_file_without_current_file_is_noop() -> None:
    presenter = SBOMPresenter(parser_loader=lambda _: pytest.fail("should not load"))

    presenter.reload_file()


def test_open_file_uses_dialog_result(monkeypatch: pytest.MonkeyPatch) -> None:
    seen_paths: list[str] = []
    presenter = SBOMPresenter(parser_loader=lambda _: sample_parsed_data())
    view = FakeView()
    presenter.attach_view(view)

    monkeypatch.setattr(
        "app.presenter.filedialog.askopenfilename",
        lambda **_: "/tmp/dialog.json",
    )
    monkeypatch.setattr(presenter, "load_sbom", lambda path: seen_paths.append(path))

    presenter.open_file()

    assert seen_paths == ["/tmp/dialog.json"]


def test_open_file_cancel_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    presenter = SBOMPresenter(parser_loader=lambda _: pytest.fail("should not load"))
    view = FakeView()
    presenter.attach_view(view)

    monkeypatch.setattr(
        "app.presenter.filedialog.askopenfilename",
        lambda **_: "",
    )

    presenter.open_file()


def test_presenter_methods_without_view_are_safe() -> None:
    presenter = SBOMPresenter(parser_loader=lambda _: sample_parsed_data())

    presenter.filter_components("requests")
    presenter.filter_dependencies("urllib3")
    presenter.show_component_details("requests")
    presenter.load_sbom("/tmp/example.json")


def test_presenter_loads_real_fixture_into_view() -> None:
    fixture_path = FIXTURES_DIR / "cyclonedx" / "cdx-1.5.json"
    presenter = SBOMPresenter(parser_loader=lambda _: detect_and_parse(str(fixture_path)))
    view = FakeView()
    presenter.attach_view(view)

    presenter.load_sbom(str(fixture_path))

    assert view.metadata is not None
    assert view.metadata["name"] == "editable-self"
    assert ("six", "1.16.0", "MIT", "pkg:pypi/six@1.16.0") in view.component_rows
    assert ("root-component", "six==1.16.0", "direct") in view.dependency_rows


def test_presenter_filters_real_fixture_rows() -> None:
    fixture_path = FIXTURES_DIR / "spdx" / "spdx-2.2.spdx"
    presenter = SBOMPresenter(parser_loader=lambda _: detect_and_parse(str(fixture_path)))
    view = FakeView()
    presenter.attach_view(view)
    presenter.load_sbom(str(fixture_path))

    presenter.filter_components("GPL-3.0-or-later")

    assert view.component_rows == [
        (
            "hello",
            "",
            "GPL-3.0-or-later",
            "git+https://github.com/swinslow/spdx-examples.git#example1/content",
        )
    ]


def test_presenter_real_fixture_detail_text_is_user_visible() -> None:
    fixture_path = FIXTURES_DIR / "swid" / "swid.xml"
    presenter = SBOMPresenter(parser_loader=lambda _: detect_and_parse(str(fixture_path)))
    view = FakeView()
    presenter.attach_view(view)
    presenter.load_sbom(str(fixture_path))

    presenter.show_component_details("Snort")

    assert "name: Snort" in view.detail_text
    assert "supplier: Cisco" in view.detail_text
