from __future__ import annotations

import tkinter as tk
from collections.abc import Sequence
from tkinter import messagebox, ttk
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from app.presenter import SBOMPresenter

from .presentation import ComponentRow, DependencyRow
from .sbom_types import Metadata
from .search_mixin import SearchMixin

_error_dialogs_enabled = True


def disable_error_dialogs_for_testing() -> None:
    global _error_dialogs_enabled
    _error_dialogs_enabled = False


class MainView(tk.Tk, SearchMixin):
    def __init__(self, presenter: "SBOMPresenter") -> None:
        super().__init__()
        self.presenter = presenter
        self.title("SBOM Viewer")
        self.geometry("1200x800")
        self.resizable(True, True)

        self.search_var = tk.StringVar()
        self.deps_search_var = tk.StringVar()

        self.build_ui()
        self.bind_events()

    def build_ui(self) -> None:
        # Toolbar frame
        toolbar_frame = ttk.Frame(self)
        toolbar_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(
            toolbar_frame, text="Open SBOM", command=self.presenter.open_file
        ).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(
            toolbar_frame, text="Reload", command=self.presenter.reload_file
        ).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(
            toolbar_frame, text="Clear", command=self.presenter.clear_view
        ).pack(side=tk.LEFT, padx=(0, 5))
        self.status_label = ttk.Label(
            toolbar_frame, text="Ready", relief=tk.SUNKEN
        )
        self.status_label.pack(side=tk.RIGHT)

        # Main container with paned window
        paned = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Left side: Tabs for main views
        self.tab_parent = ttk.Notebook(paned)
        paned.add(self.tab_parent, weight=4)

        self.components_tab = ttk.Frame(self.tab_parent)
        self.dependencies_tab = ttk.Frame(self.tab_parent)
        self.metadata_tab = ttk.Frame(self.tab_parent)

        self.tab_parent.add(self.components_tab, text="Components")
        self.tab_parent.add(self.dependencies_tab, text="Dependencies")
        self.tab_parent.add(self.metadata_tab, text="Metadata")

        # Right side: Component details panel
        self.details_frame = ttk.LabelFrame(
            paned, text="Component Details", width=300
        )
        paned.add(self.details_frame, weight=1)

        self.build_components_view()
        self.build_dependencies_view()
        self.build_metadata_view()
        self.build_details_view()

    def build_components_view(self) -> None:
        self.create_search_frame(
            self.components_tab,
            self.search_var,
            self.presenter,
            "filter_components",
        )

        # Components treeview
        tree_frame = ttk.Frame(self.components_tab)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        columns = ("name", "version", "license", "purl")
        self.components_tree = ttk.Treeview(
            tree_frame, columns=columns, show="headings", height=20
        )

        for col in columns:
            self.components_tree.heading(col, text=col.title())
            self.components_tree.column(
                col, width=150, minwidth=100, stretch=True
            )

        # Scrollbars
        v_scrollbar = ttk.Scrollbar(
            tree_frame, orient=tk.VERTICAL, command=self.components_tree.yview
        )
        h_scrollbar = ttk.Scrollbar(
            tree_frame,
            orient=tk.HORIZONTAL,
            command=self.components_tree.xview,
        )
        self.components_tree.configure(
            yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set
        )

        self.components_tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")

        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        # Bind selection
        self.components_tree.bind(
            "<<TreeviewSelect>>", self.on_component_select
        )

    def build_dependencies_view(self) -> None:
        self.create_search_frame(
            self.dependencies_tab,
            self.deps_search_var,
            self.presenter,
            "filter_dependencies",
        )

        # Dependencies treeview (simplified for MVP)
        tree_frame = ttk.Frame(self.dependencies_tab)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        columns = ("from", "to", "type")
        self.deps_tree = ttk.Treeview(
            tree_frame, columns=columns, show="headings", height=20
        )

        for col in columns:
            self.deps_tree.heading(col, text=col.title())
            self.deps_tree.column(col, width=200, minwidth=100)

        v_scrollbar = ttk.Scrollbar(
            tree_frame, orient=tk.VERTICAL, command=self.deps_tree.yview
        )
        self.deps_tree.configure(yscrollcommand=v_scrollbar.set)

        self.deps_tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

    def build_metadata_view(self) -> None:
        # Metadata display (text widget for simplicity)
        self.metadata_text = tk.Text(
            self.metadata_tab, wrap=tk.WORD, height=25
        )
        scrollbar = ttk.Scrollbar(
            self.metadata_tab,
            orient=tk.VERTICAL,
            command=self.metadata_text.yview,
        )
        self.metadata_text.configure(yscrollcommand=scrollbar.set)

        self.metadata_text.pack(
            side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5
        )
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)

    def build_details_view(self) -> None:
        # Component details (labels that update)
        self.details_text = tk.Text(
            self.details_frame, wrap=tk.WORD, height=30, state=tk.DISABLED
        )
        scrollbar = ttk.Scrollbar(
            self.details_frame,
            orient=tk.VERTICAL,
            command=self.details_text.yview,
        )
        self.details_text.configure(yscrollcommand=scrollbar.set)

        self.details_text.pack(
            side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5
        )
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)

    def bind_events(self) -> None:
        self.bind("<Configure>", self.on_resize)

    def on_resize(self, event: tk.Event) -> None:
        """Handle window resize for proper column stretching."""
        pass  # Treeviews handle this automatically with stretch=True

    def on_component_select(self, event: tk.Event) -> None:
        del event
        selection = self.components_tree.selection()
        if selection:
            item = self.components_tree.item(selection[0])
            component_id = item["values"][0]  # Use name as ID for now
            self.presenter.show_component_details(component_id)

    # Public methods for the presenter to call
    def set_metadata(self, metadata: Metadata) -> None:
        self.metadata_text.config(state=tk.NORMAL)
        self.metadata_text.delete(1.0, tk.END)
        for key, value in metadata.items():
            self.metadata_text.insert(tk.END, f"{key}: {value}\n")
        self.metadata_text.config(state=tk.DISABLED)
        self.tab_parent.select(self.metadata_tab)  # type: ignore

    def set_component_rows(self, rows: list[ComponentRow]) -> None:
        # Clear existing
        for item in self.components_tree.get_children():
            self.components_tree.delete(item)

        # Populate
        for row in rows:
            self.components_tree.insert("", tk.END, values=row)

        self.status_label.config(text=f"Loaded {len(rows)} components")

    def set_dependency_rows(self, rows: list[DependencyRow]) -> None:
        for item in self.deps_tree.get_children():
            self.deps_tree.delete(item)

        for row in rows:
            self.deps_tree.insert("", tk.END, values=row)

    def show_component_details(self, details: str) -> None:
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, details)
        self.details_text.config(state=tk.DISABLED)

    def show_status(self, message: str) -> None:
        self.status_label.config(text=message)

    def show_error(self, message: str) -> None:
        if _error_dialogs_enabled:
            messagebox.showerror("Error", message)
        self.show_status("Error loading file")

    def snapshot_state(self) -> dict[str, Any]:
        return {
            "status": self.status_label.cget("text"),
            "metadata_text": self.metadata_text.get("1.0", "end-1c"),
            "details_text": self.details_text.get("1.0", "end-1c"),
            "components": self._tree_values(self.components_tree),
            "dependencies": self._tree_values(self.deps_tree),
        }

    def clear_all(self) -> None:
        # Clear all views
        for tree in [self.components_tree, self.deps_tree]:
            for item in tree.get_children():
                tree.delete(item)

        self.metadata_text.config(state=tk.NORMAL)
        self.metadata_text.delete(1.0, tk.END)
        self.metadata_text.config(state=tk.DISABLED)

        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, "Select a component to view details.")
        self.details_text.config(state=tk.DISABLED)

        self.search_var.set("")
        self.deps_search_var.set("")
        self.show_status("Cleared")

    @staticmethod
    def _tree_values(tree: ttk.Treeview) -> list[list[str]]:
        rows: list[list[str]] = []
        for item_id in tree.get_children():
            values = tree.item(item_id)["values"]
            if isinstance(values, Sequence):
                rows.append([str(value) for value in values])
        return rows

    def get_open_file_callback(self) -> Callable[[], None]:
        """Return callback for presenter to trigger file dialog."""
        return self.presenter.open_file
