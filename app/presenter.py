import os
from tkinter import filedialog
from typing import Callable, Optional, Protocol

from .models import SBOMModel
from .parsers import detect_and_parse
from .presentation import ComponentRow, DependencyRow, SBOMFormatter
from .sbom_types import Metadata, NormalizedSBOM


class SBOMView(Protocol):
    def set_metadata(self, metadata: Metadata) -> None: ...
    def set_component_rows(self, rows: list[ComponentRow]) -> None: ...
    def set_dependency_rows(self, rows: list[DependencyRow]) -> None: ...
    def show_component_details(self, details: str) -> None: ...
    def show_status(self, message: str) -> None: ...
    def show_error(self, message: str) -> None: ...
    def clear_all(self) -> None: ...


class SBOMPresenter:
    def __init__(
        self,
        model: Optional[SBOMModel] = None,
        parser_loader: Callable[[str], NormalizedSBOM] = detect_and_parse,
        formatter: Optional[SBOMFormatter] = None,
    ) -> None:
        self.view: Optional[SBOMView] = None
        self.model: SBOMModel = model or SBOMModel()
        self.parser_loader = parser_loader
        self.formatter = formatter or SBOMFormatter()
        self.current_file_path: Optional[str] = None

    def attach_view(self, view: SBOMView) -> None:
        """Connect presenter to the view."""
        self.view = view

    def open_file(self) -> None:
        """Handle the Open SBOM action."""
        if not self.view:
            return

        file_path = filedialog.askopenfilename(
            title="Select SBOM file",
            filetypes=[
                ("SBOM Files", "*.json *.xml *.spdx *.cdx *.swidtag"),
                ("JSON", "*.json"),
                ("XML", "*.xml"),
                ("All Files", "*.*"),
            ],
        )

        if file_path:
            self.load_sbom(file_path)

    def reload_file(self) -> None:
        """Reload current file."""
        if self.current_file_path:
            self.load_sbom(self.current_file_path)

    def clear_view(self) -> None:
        """Clear all data."""
        self.model.clear()
        if self.view:
            self.view.clear_all()

    def load_sbom(self, file_path: str) -> None:
        """Load, parse, and present an SBOM file."""
        if not self.view:
            return

        try:
            self.view.show_status(f"Loading {os.path.basename(file_path)}...")

            parsed_data = self.parser_loader(file_path)
            self.load_parsed_data(parsed_data)
            self.current_file_path = file_path

            self.view.show_status(
                f"Loaded SBOM: {len(self.model.components)} components"
            )

        except Exception as exc:
            error_msg = f"Failed to load SBOM: {exc}"
            self.view.show_error(error_msg)
            self.view.show_status("Load failed")

    def update_views(self) -> None:
        """Update the view with current model data."""
        if not self.view:
            return

        self.view.set_metadata(self.model.get_metadata())
        self.view.set_component_rows(
            self.formatter.component_rows(self.model.get_components())
        )
        self.view.set_dependency_rows(
            self.formatter.dependency_rows(self.model.get_dependencies())
        )

    def load_parsed_data(self, parsed_data: NormalizedSBOM) -> None:
        """Load already-parsed data and refresh the view."""
        self.model.load_from_parsed(parsed_data)
        self.update_views()

    def filter_components(self, search_text: str) -> None:
        """Filter components by search text."""
        if not self.view:
            return

        self.view.set_component_rows(
            self.formatter.component_rows(
                self.model.get_components(filter_text=search_text)
            )
        )

    def show_component_details(self, component_id: str) -> None:
        """Show details for the selected component."""
        if not self.view:
            return

        self.view.show_component_details(
            self.formatter.component_details(
                self.model.get_component_details(component_id)
            )
        )

    def filter_dependencies(self, search_text: str) -> None:
        """Filter dependencies by search text."""
        if not self.view:
            return

        self.view.set_dependency_rows(
            self.formatter.dependency_rows(
                self.model.get_dependencies(filter_text=search_text)
            )
        )
