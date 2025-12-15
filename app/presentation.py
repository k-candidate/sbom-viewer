from __future__ import annotations

from typing import Any

from app.sbom_types import Component, NormalizedDependency

ComponentRow = tuple[str, str, str, str]
DependencyRow = tuple[str, str, str]


class SBOMFormatter:
    """Format normalized SBOM data for presentation layers."""

    def component_rows(
        self,
        components: list[Component],
    ) -> list[ComponentRow]:
        return [
            (
                component["name"],
                component["version"],
                ", ".join(component["licenses"]),
                component["purl"],
            )
            for component in components
        ]

    def dependency_rows(
        self,
        dependencies: list[NormalizedDependency],
    ) -> list[DependencyRow]:
        return [
            (
                dependency["from"],
                ", ".join(dependency["to"]) if dependency["to"] else "None",
                dependency["type"],
            )
            for dependency in dependencies
        ]

    def component_details(self, component: Component | None) -> str:
        if component is None:
            return "Component not found."

        preferred_order = [
            "name",
            "version",
            "licenses",
            "purl",
            "type",
            "supplier",
            "hashes",
            "description",
        ]
        detail_map: dict[str, Any] = dict(component)
        lines: list[str] = []

        for key in preferred_order:
            if key in detail_map:
                lines.extend(self._format_detail_line(key, detail_map[key]))

        extra_keys = sorted(
            key for key in detail_map if key not in preferred_order
        )
        for key in extra_keys:
            lines.extend(self._format_detail_line(key, detail_map[key]))

        return "\n".join(lines)

    def _format_detail_line(self, key: str, value: Any) -> list[str]:
        if isinstance(value, list):
            return [
                f"{key}: {', '.join(str(item) for item in value) or 'None'}"
            ]

        if isinstance(value, dict):
            if not value:
                return [f"{key}: None"]

            lines = [f"{key}:"]
            for nested_key, nested_value in sorted(value.items()):
                lines.append(f"  {nested_key}: {nested_value}")
            return lines

        return [f"{key}: {value or 'None'}"]
