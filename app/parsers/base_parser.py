from abc import ABC, abstractmethod
from typing import Any

from app.sbom_types import (
    Component,
    Metadata,
    NormalizedDependency,
    NormalizedSBOM,
)


class BaseSBOMParser(ABC):
    """Abstract base class for all SBOM parsers."""

    @abstractmethod
    def can_parse(
        self, file_path: str, content: bytes, content_str: str
    ) -> bool:
        """
        Determine if this parser can handle the given file.

        Args:
            file_path: Path to file
            content: Raw bytes content
            content_str: Decoded string content

        Returns:
            True if this parser can parse the file
        """
        pass

    @abstractmethod
    def parse(
        self, file_path: str, content: bytes, content_str: str
    ) -> NormalizedSBOM:
        """
        Parse the file into normalized SBOM structure.

        Args:
            file_path: Path to file
            content: Raw bytes content
            content_str: Decoded string content

        Returns:
            Normalized SBOM dict with metadata, components, dependencies
        """
        pass

    def get_extensions(self) -> list[str]:
        """
        Get file extensions this parser supports.

        Returns:
            List of supported extensions (e.g. ['.json', '.xml'])
        """
        return []

    def _normalize_metadata(self, raw_metadata: dict[str, Any]) -> Metadata:
        """Helper to normalize metadata fields."""
        return {
            "name": self._clean_text(raw_metadata.get("name", "")),
            "version": self._clean_text(raw_metadata.get("version", "")),
            "creation_date": self._clean_text(
                raw_metadata.get("creation_date", "")
            ),
            "supplier": self._clean_text(raw_metadata.get("supplier", "")),
            "spec_version": self._clean_text(
                raw_metadata.get("spec_version", "")
            ),
        }

    def _normalize_component(self, raw_comp: dict[str, Any]) -> Component:
        """Helper to normalize a single component."""
        return {
            "name": self._clean_text(raw_comp.get("name", "")),
            "version": self._clean_text(raw_comp.get("version", "")),
            "licenses": self._normalize_string_list(
                raw_comp.get("licenses", [])
            ),
            "purl": self._clean_text(raw_comp.get("purl", "")),
            "type": self._clean_text(raw_comp.get("type", "")),
            "supplier": self._clean_text(raw_comp.get("supplier", "")),
            "hashes": {
                self._clean_text(key): self._clean_text(value)
                for key, value in raw_comp.get("hashes", {}).items()
                if self._clean_text(key) and self._clean_text(value)
            },
            "description": self._clean_text(raw_comp.get("description", "")),
        }

    @staticmethod
    def _clean_text(value: Any) -> str:
        if value is None:
            return ""
        return str(value).strip()

    def _normalize_string_list(self, values: list[Any]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            cleaned = self._clean_text(value)
            if cleaned and cleaned not in normalized:
                normalized.append(cleaned)
        return normalized

    def _build_document(
        self,
        metadata: Metadata,
        components: list[Component],
        dependencies: list[NormalizedDependency],
    ) -> NormalizedSBOM:
        return {
            "metadata": metadata,
            "components": components,
            "dependencies": self._normalize_dependencies(dependencies),
        }

    def _normalize_dependencies(
        self, dependencies: list[NormalizedDependency]
    ) -> list[NormalizedDependency]:
        normalized: list[NormalizedDependency] = []
        seen: set[tuple[str, tuple[str, ...], str]] = set()

        for dependency in dependencies:
            dep_from = self._clean_text(dependency.get("from", ""))
            dep_to = self._normalize_string_list(dependency.get("to", []))
            dep_type = self._clean_text(dependency.get("type", ""))

            if not dep_from:
                continue

            key = (dep_from, tuple(dep_to), dep_type)
            if key in seen:
                continue

            seen.add(key)
            normalized.append(
                {
                    "from": dep_from,
                    "to": dep_to,
                    "type": dep_type,
                }
            )

        return normalized
