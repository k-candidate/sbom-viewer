from copy import deepcopy
from typing import Optional

from app.sbom_types import (
    Component,
    Metadata,
    NormalizedDependency,
    NormalizedSBOM,
)


class SBOMModel:
    def __init__(self) -> None:
        self.metadata: Metadata = self._empty_metadata()
        self.components: list[Component] = []
        self.dependencies: list[NormalizedDependency] = []

    def clear(self) -> None:
        """Clear all data."""
        self.metadata = self._empty_metadata()
        self.components.clear()
        self.dependencies.clear()

    def load_from_parsed(self, parsed_data: NormalizedSBOM) -> None:
        """Load normalized data from parser output."""
        self.clear()

        self.metadata = deepcopy(parsed_data["metadata"])
        self.components = deepcopy(parsed_data["components"])
        self.dependencies = deepcopy(parsed_data["dependencies"])

    def get_metadata(self) -> Metadata:
        """Get metadata dictionary."""
        return self.metadata.copy()

    def get_components(
        self, filter_text: Optional[str] = None
    ) -> list[Component]:
        """Get components, optionally filtered by search text."""
        search_text = self._normalize_filter_text(filter_text)
        if not search_text:
            return self.components.copy()

        return [
            comp
            for comp in self.components
            if search_text in str(comp.get("name", "")).lower()
            or search_text in str(comp.get("version", "")).lower()
            or search_text in str(comp.get("purl", "")).lower()
            or search_text
            in " ".join(str(item) for item in comp.get("licenses", [])).lower()
        ]

    def get_dependencies(
        self, filter_text: Optional[str] = None
    ) -> list[NormalizedDependency]:
        """Get dependencies, optionally filtered by search text."""
        search_text = self._normalize_filter_text(filter_text)
        if not search_text:
            return self.dependencies.copy()

        return [
            dep
            for dep in self.dependencies
            if search_text in str(dep.get("from", "")).lower()
            or search_text
            in " ".join(str(target) for target in dep.get("to", [])).lower()
        ]

    def get_component_details(self, component_id: str) -> Optional[Component]:
        """Get full details for a component by name/ID."""
        normalized_component_id = component_id.strip().lower()
        for comp in self.components:
            name = str(comp.get("name", "")).lower()
            purl = str(comp.get("purl", "")).lower()
            if (
                name == normalized_component_id
                or purl == normalized_component_id
                or purl.endswith(normalized_component_id)
            ):
                return comp
        return None

    def get_component_by_purl(self, purl: str) -> Optional[Component]:
        """Helper to find component by PURL."""
        normalized_purl = purl.strip().lower()
        for comp in self.components:
            if str(comp.get("purl", "")).lower() == normalized_purl:
                return comp
        return None

    @staticmethod
    def _normalize_filter_text(filter_text: Optional[str]) -> str:
        return (filter_text or "").strip().lower()

    @staticmethod
    def _empty_metadata() -> Metadata:
        return {
            "name": "",
            "version": "",
            "creation_date": "",
            "supplier": "",
            "spec_version": "",
        }


# Normalized data structure that all parsers must output
NORMALIZED_SBOM_SCHEMA = {
    "metadata": {
        "name": str,
        "version": str,
        "creation_date": str,
        "supplier": str,
        "spec_version": str,
        # Add more common fields as needed
    },
    "components": [
        {
            "name": str,
            "version": str,
            "licenses": list[str],
            "purl": str,
            "type": str,
            "supplier": str,
            "hashes": dict[str, str],
            "description": str,
            # Add more common fields
        }
    ],
    "dependencies": [
        {
            "from": str,  # component name or PURL
            "to": list[str],  # dependent components
            "type": str,  # "direct", "indirect", etc.
        }
    ],
}
