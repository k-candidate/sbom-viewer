from dataclasses import dataclass, field
from typing import Any

import pytest

tk = pytest.importorskip("tkinter")

from app.view import MainView


@dataclass
class FakePresenter:
    component_filters: list[str] = field(default_factory=list)
    dependency_filters: list[str] = field(default_factory=list)
    selected_components: list[str] = field(default_factory=list)
    open_calls: int = 0
    reload_calls: int = 0
    clear_calls: int = 0

    def open_file(self) -> None:
        self.open_calls += 1

    def reload_file(self) -> None:
        self.reload_calls += 1

    def clear_view(self) -> None:
        self.clear_calls += 1

    def filter_components(self, search_text: str) -> None:
        self.component_filters.append(search_text)

    def filter_dependencies(self, search_text: str) -> None:
        self.dependency_filters.append(search_text)

    def show_component_details(self, component_id: str) -> None:
        self.selected_components.append(component_id)


@pytest.fixture
def main_view() -> MainView:
    presenter = FakePresenter()
    try:
        view = MainView(presenter)
    except tk.TclError as exc:
        pytest.skip(f"Tk is not available in this environment: {exc}")

    view.withdraw()
    view.update_idletasks()
    try:
        yield view
    finally:
        view.update_idletasks()
        view.destroy()


def tree_values(tree: Any) -> list[tuple[str, ...]]:
    return [tuple(tree.item(item_id)["values"]) for item_id in tree.get_children()]


def test_set_component_rows_populates_tree(main_view: MainView) -> None:
    main_view.set_component_rows(
        [
            ("requests", "2.31.0", "Apache-2.0", "pkg:pypi/requests@2.31.0"),
            ("flask", "3.0.1", "BSD-3-Clause", "pkg:pypi/flask@3.0.1"),
        ]
    )

    assert tree_values(main_view.components_tree) == [
        ("requests", "2.31.0", "Apache-2.0", "pkg:pypi/requests@2.31.0"),
        ("flask", "3.0.1", "BSD-3-Clause", "pkg:pypi/flask@3.0.1"),
    ]
    assert main_view.status_label.cget("text") == "Loaded 2 components"


def test_set_component_rows_replaces_existing_tree_rows(main_view: MainView) -> None:
    main_view.set_component_rows(
        [("requests", "2.31.0", "Apache-2.0", "pkg:pypi/requests@2.31.0")]
    )

    main_view.set_component_rows(
        [("flask", "3.0.1", "BSD-3-Clause", "pkg:pypi/flask@3.0.1")]
    )

    assert tree_values(main_view.components_tree) == [
        ("flask", "3.0.1", "BSD-3-Clause", "pkg:pypi/flask@3.0.1")
    ]


def test_set_dependency_rows_populates_tree(main_view: MainView) -> None:
    main_view.set_dependency_rows(
        [
            ("requests", "urllib3", "direct"),
            ("flask", "jinja2, werkzeug", "direct"),
        ]
    )

    assert tree_values(main_view.deps_tree) == [
        ("requests", "urllib3", "direct"),
        ("flask", "jinja2, werkzeug", "direct"),
    ]


def test_set_dependency_rows_replaces_existing_tree_rows(main_view: MainView) -> None:
    main_view.set_dependency_rows([("requests", "urllib3", "direct")])

    main_view.set_dependency_rows([("flask", "jinja2", "direct")])

    assert tree_values(main_view.deps_tree) == [
        ("flask", "jinja2", "direct")
    ]


def test_set_metadata_updates_text_and_selects_tab(main_view: MainView) -> None:
    main_view.set_metadata({"name": "demo", "version": "1.0.0"})

    metadata_text = main_view.metadata_text.get("1.0", "end-1c")
    assert metadata_text == "name: demo\nversion: 1.0.0\n"
    assert str(main_view.tab_parent.select()) == str(main_view.metadata_tab)


def test_show_component_details_updates_detail_panel(main_view: MainView) -> None:
    main_view.show_component_details("name: requests\nversion: 2.31.0")

    assert main_view.details_text.get("1.0", "end-1c") == (
        "name: requests\nversion: 2.31.0"
    )


def test_show_component_details_can_clear_panel(main_view: MainView) -> None:
    main_view.show_component_details("details")
    main_view.show_component_details("")

    assert main_view.details_text.get("1.0", "end-1c") == ""


def test_clear_all_resets_widgets(main_view: MainView) -> None:
    main_view.set_component_rows(
        [("requests", "2.31.0", "Apache-2.0", "pkg:pypi/requests@2.31.0")]
    )
    main_view.set_dependency_rows([("requests", "urllib3", "direct")])
    main_view.set_metadata({"name": "demo"})
    main_view.show_component_details("details")
    main_view.search_var.set("req")
    main_view.deps_search_var.set("urllib3")

    main_view.clear_all()

    assert tree_values(main_view.components_tree) == []
    assert tree_values(main_view.deps_tree) == []
    assert main_view.metadata_text.get("1.0", "end-1c") == ""
    assert main_view.details_text.get("1.0", "end-1c") == (
        "Select a component to view details."
    )
    assert main_view.search_var.get() == ""
    assert main_view.deps_search_var.get() == ""
    assert main_view.status_label.cget("text") == "Cleared"


def test_on_component_select_notifies_presenter(main_view: MainView) -> None:
    main_view.set_component_rows(
        [("requests", "2.31.0", "Apache-2.0", "pkg:pypi/requests@2.31.0")]
    )

    item_id = main_view.components_tree.get_children()[0]
    main_view.components_tree.selection_set(item_id)
    main_view.on_component_select(event=None)  # type: ignore[arg-type]

    assert main_view.presenter.selected_components == ["requests"]


def test_search_variables_trigger_presenter_filters(main_view: MainView) -> None:
    main_view.search_var.set("requests")
    main_view.deps_search_var.set("urllib3")
    main_view.update_idletasks()

    assert main_view.presenter.component_filters[-1] == "requests"
    assert main_view.presenter.dependency_filters[-1] == "urllib3"


def test_empty_row_updates_are_supported(main_view: MainView) -> None:
    main_view.set_component_rows([])
    main_view.set_dependency_rows([])

    assert tree_values(main_view.components_tree) == []
    assert tree_values(main_view.deps_tree) == []
    assert main_view.status_label.cget("text") == "Loaded 0 components"


def test_get_open_file_callback_returns_presenter_handler(main_view: MainView) -> None:
    callback = main_view.get_open_file_callback()
    callback()

    assert main_view.presenter.open_calls == 1


def test_show_error_uses_messagebox_and_updates_status(
    main_view: MainView, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "app.view.messagebox.showerror",
        lambda title, message: captured.append((title, message)),
    )

    main_view.show_error("boom")

    assert captured == [("Error", "boom")]
    assert main_view.status_label.cget("text") == "Error loading file"


def test_snapshot_state_returns_rendered_widget_data(main_view: MainView) -> None:
    main_view.set_component_rows(
        [("requests", "2.31.0", "Apache-2.0", "pkg:pypi/requests@2.31.0")]
    )
    main_view.set_dependency_rows([("requests", "urllib3", "direct")])
    main_view.set_metadata({"name": "demo", "version": "1.0.0"})
    main_view.show_component_details("name: requests")

    assert main_view.snapshot_state() == {
        "status": "Loaded 1 components",
        "metadata_text": "name: demo\nversion: 1.0.0\n",
        "details_text": "name: requests",
        "components": [
            ["requests", "2.31.0", "Apache-2.0", "pkg:pypi/requests@2.31.0"]
        ],
        "dependencies": [["requests", "urllib3", "direct"]],
    }
