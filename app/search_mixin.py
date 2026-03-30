import tkinter as tk
from tkinter import ttk
from typing import Any


class SearchMixin:
    """Reusable search bar for treeview tabs."""

    def create_search_frame(
        self,
        parent: tk.Widget,
        search_var: tk.StringVar,
        presenter: Any,
        filter_method: str,
    ) -> ttk.Frame:
        """Create standardized search frame."""
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(frame, text="Search:").pack(side=tk.LEFT)
        ttk.Entry(frame, textvariable=search_var, width=30).pack(
            side=tk.LEFT, padx=(5, 10)
        )
        ttk.Button(
            frame, text="Clear Search", command=lambda: search_var.set("")
        ).pack(side=tk.LEFT)

        # Auto-filter on typing
        search_var.trace_add(
            "write",
            lambda *_: getattr(presenter, filter_method)(search_var.get()),
        )

        return frame
