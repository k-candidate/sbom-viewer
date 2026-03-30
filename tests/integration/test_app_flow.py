from typing import Any

import pytest

tk = pytest.importorskip("tkinter")

from app.parsers import detect_and_parse
from app.presenter import SBOMPresenter
from app.view import MainView
from tests.support import FIXTURES_DIR


def tree_values(tree: Any) -> list[tuple[str, ...]]:
    return [tuple(tree.item(item_id)["values"]) for item_id in tree.get_children()]


@pytest.fixture
def app_flow() -> tuple[SBOMPresenter, MainView]:
    presenter = SBOMPresenter()
    try:
        view = MainView(presenter)
    except tk.TclError as exc:
        pytest.skip(f"Tk is not available in this environment: {exc}")

    presenter.attach_view(view)
    view.withdraw()
    view.update_idletasks()
    try:
        yield presenter, view
    finally:
        view.update_idletasks()
        view.destroy()


def test_load_sbom_updates_real_view_with_fixture_data(
    app_flow: tuple[SBOMPresenter, MainView],
) -> None:
    presenter, view = app_flow
    fixture_path = FIXTURES_DIR / "cyclonedx" / "cdx-1.5.json"

    presenter.load_sbom(str(fixture_path))

    assert presenter.current_file_path == str(fixture_path)
    component_rows = tree_values(view.components_tree)
    dependency_rows = tree_values(view.deps_tree)

    assert view.status_label.cget("text") == (
        f"Loaded SBOM: {len(component_rows)} components"
    )
    assert ("six", "1.16.0", "MIT", "pkg:pypi/six@1.16.0") in component_rows
    assert ("root-component", "six==1.16.0", "direct") in dependency_rows
    assert "name: editable-self" in view.metadata_text.get("1.0", "end-1c")


def test_search_and_selection_flow_updates_real_widgets(
    app_flow: tuple[SBOMPresenter, MainView],
) -> None:
    presenter, view = app_flow
    fixture_path = FIXTURES_DIR / "cyclonedx" / "cdx-1.5.json"

    presenter.load_sbom(str(fixture_path))
    view.search_var.set("six")
    view.deps_search_var.set("1.16.0")
    view.update_idletasks()

    assert tree_values(view.components_tree) == [
        ("six", "1.16.0", "MIT", "pkg:pypi/six@1.16.0")
    ]
    assert tree_values(view.deps_tree) == [
        ("root-component", "six==1.16.0", "direct"),
        ("six==1.16.0", "None", "direct"),
    ]

    item_id = view.components_tree.get_children()[0]
    view.components_tree.selection_set(item_id)
    view.on_component_select(event=None)  # type: ignore[arg-type]

    details_text = view.details_text.get("1.0", "end-1c")
    assert "name: six" in details_text
    assert "licenses: MIT" in details_text


def test_reload_file_refreshes_real_view_after_model_clear(
    app_flow: tuple[SBOMPresenter, MainView],
) -> None:
    presenter, view = app_flow
    fixture_path = FIXTURES_DIR / "spdx" / "spdx-2.2.spdx"

    presenter.load_sbom(str(fixture_path))
    presenter.clear_view()

    assert tree_values(view.components_tree) == []

    presenter.reload_file()

    assert presenter.current_file_path == str(fixture_path)
    assert tree_values(view.components_tree) == [
        (
            "hello",
            "",
            "GPL-3.0-or-later",
            "git+https://github.com/swinslow/spdx-examples.git#example1/content",
        )
    ]


def test_open_file_dialog_flow_loads_real_fixture(
    app_flow: tuple[SBOMPresenter, MainView],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    presenter, view = app_flow
    fixture_path = FIXTURES_DIR / "swid" / "swid.xml"

    monkeypatch.setattr(
        "app.presenter.filedialog.askopenfilename",
        lambda **_: str(fixture_path),
    )

    presenter.open_file()

    assert presenter.current_file_path == str(fixture_path)
    assert tree_values(view.components_tree)[0] == ("Snort", "3.0", "", "Cisco-Snort-3.0")
    assert view.status_label.cget("text") == "Loaded SBOM: 1 components"


def test_load_sbom_error_flow_updates_real_view_status(
    app_flow: tuple[SBOMPresenter, MainView],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    presenter, view = app_flow
    captured_errors: list[tuple[str, str]] = []

    monkeypatch.setattr(
        "app.view.messagebox.showerror",
        lambda title, message: captured_errors.append((title, message)),
    )
    presenter.parser_loader = lambda _: (_ for _ in ()).throw(ValueError("boom"))

    presenter.load_sbom("broken.json")

    assert captured_errors == [("Error", "Failed to load SBOM: boom")]
    assert view.status_label.cget("text") == "Load failed"
