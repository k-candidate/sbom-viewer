import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from app.sbom_types import (
    Component,
    Metadata,
    NormalizedDependency,
    NormalizedSBOM,
)

from .base_parser import BaseSBOMParser


class CycloneDXParser(BaseSBOMParser):
    """Parser for CycloneDX SBOM format (JSON and XML)."""

    def can_parse(
        self, file_path: str, content: bytes, content_str: str
    ) -> bool:
        """Detect CycloneDX by extension and content markers."""
        file_ext = Path(file_path).suffix.lower()

        # File extension check
        if file_ext in [".cdx", ".cdx.json", ".json", ".xml"]:
            # JSON CycloneDX: look for bomFormat or bomFormat == "CycloneDX"
            if '"bomFormat":' in content_str or (
                '"$schema":' in content_str
                and "cyclonedx" in content_str.lower()
            ):
                return True

            # XML CycloneDX: look for bom root element
            if (
                "<bom" in content_str.lower()
                or 'xmlns="http://cyclonedx.org/schema/bom' in content_str
            ):
                return True

        return False

    def parse(
        self, file_path: str, content: bytes, content_str: str
    ) -> NormalizedSBOM:
        """Parse CycloneDX into normalized structure."""
        file_ext = Path(file_path).suffix.lower()

        # XML first (more reliable than string checks)
        if file_ext == ".xml" or "<bom" in content_str.lower()[:500]:
            return self._parse_xml_cdx(content_str)
        else:
            # JSON fallback
            return self._parse_json_cdx(content_str)

    def _parse_json_cdx(self, content_str: str) -> NormalizedSBOM:
        """Parse CycloneDX JSON format."""
        try:
            data = json.loads(content_str)

            metadata = self._parse_json_metadata(data)
            components = self._parse_json_components(data)
            dependencies = self._extract_dependencies_json(data)

            return self._build_document(metadata, components, dependencies)

        except json.JSONDecodeError:
            raise ValueError("Invalid CycloneDX JSON format")

    def _parse_xml_cdx(self, content_str: str) -> NormalizedSBOM:
        """Parse CycloneDX XML format."""
        try:
            root = ET.fromstring(content_str)

            # Dynamically determine namespace
            if "}" in root.tag:
                ns = root.tag.split("}")[0] + "}"
            else:
                ns = ""

            metadata = self._parse_xml_metadata(root, ns)
            components = self._parse_xml_components(root, ns)
            dependencies = self._extract_dependencies_xml(root, ns)

            return self._build_document(metadata, components, dependencies)

        except ET.ParseError:
            raise ValueError("Invalid CycloneDX XML format")

    def _parse_json_metadata(self, data: dict[str, Any]) -> Metadata:
        return self._normalize_metadata(
            {
                "name": data.get("metadata", {})
                .get("component", {})
                .get("name", ""),
                "version": data.get("metadata", {})
                .get("component", {})
                .get("version", ""),
                "creation_date": data.get("metadata", {}).get("timestamp", ""),
                "supplier": data.get("metadata", {})
                .get("component", {})
                .get("supplier", {})
                .get("name", ""),
                "spec_version": data.get(
                    "specVersion", data.get("bomFormat", "")
                ),
            }
        )

    def _parse_json_components(self, data: dict[str, Any]) -> list[Component]:
        return [
            self._normalize_component(
                {
                    "name": comp.get("name", ""),
                    "version": comp.get("version", ""),
                    "licenses": self._extract_licenses(comp),
                    "purl": comp.get("purl", ""),
                    "type": comp.get("type", ""),
                    "supplier": comp.get("supplier", {}).get("name", ""),
                    "hashes": {
                        hash_entry.get("alg"): hash_entry.get("content")
                        for hash_entry in comp.get("hashes", [])
                    },
                    "description": comp.get("description", ""),
                }
            )
            for comp in data.get("components", [])
        ]

    def _parse_xml_metadata(self, root: ET.Element, ns: str) -> Metadata:
        metadata = self._normalize_metadata(
            {"spec_version": self._extract_xml_spec_version(root)}
        )
        metadata_elem = root.find(f".//{ns}metadata")
        if metadata_elem is None:
            return metadata

        component = metadata_elem.find(f".//{ns}component")
        if component is not None:
            metadata["name"] = self._find_xml_text(component, ns, "name")
            metadata["version"] = self._find_xml_text(component, ns, "version")
            supplier = component.find(f".//{ns}supplier")
            if supplier is not None:
                metadata["supplier"] = self._find_xml_text(
                    supplier, ns, "name"
                )

        metadata["creation_date"] = self._find_xml_text(
            metadata_elem, ns, "timestamp"
        )
        return metadata

    def _extract_xml_spec_version(self, root: ET.Element) -> str:
        if "}" not in root.tag:
            return self._clean_text(root.get("version", ""))

        namespace = root.tag.split("}", 1)[0].lstrip("{")
        marker = "/schema/bom/"
        if marker not in namespace:
            return self._clean_text(root.get("version", ""))

        return namespace.split(marker, 1)[1]

    def _parse_xml_components(
        self, root: ET.Element, ns: str
    ) -> list[Component]:
        components_section = root.find(f"{ns}components")
        if components_section is None:
            return []

        return [
            self._normalize_component(
                self._extract_xml_component_data(component, ns)
            )
            for component in components_section.findall(f"{ns}component")
        ]

    def _extract_xml_component_data(
        self, comp_elem: ET.Element, ns: str
    ) -> dict[str, Any]:
        comp_data: dict[str, Any] = {
            "name": self._find_xml_text(comp_elem, ns, "name"),
            "version": self._find_xml_text(comp_elem, ns, "version"),
            "licenses": self._extract_xml_licenses(comp_elem, ns),
            "purl": self._find_xml_text(comp_elem, ns, "purl")
            or comp_elem.get("bom-ref", ""),
            "type": comp_elem.get("type", ""),
            "supplier": "",
            "hashes": self._extract_xml_hashes(comp_elem, ns),
            "description": self._find_xml_text(comp_elem, ns, "description"),
        }

        supplier = comp_elem.find(f".//{ns}supplier")
        if supplier is not None:
            comp_data["supplier"] = self._find_xml_text(supplier, ns, "name")

        self._populate_name_version_from_purl(comp_data)
        return comp_data

    def _extract_xml_licenses(
        self, comp_elem: ET.Element, ns: str
    ) -> list[str]:
        licenses: list[str] = []
        for license_elem in comp_elem.findall(f".//{ns}license"):
            license_id = self._find_xml_text(license_elem, ns, "id")
            license_name = self._find_xml_text(license_elem, ns, "name")
            if license_id:
                licenses.append(license_id)
            if license_name:
                licenses.append(license_name)
        return licenses

    def _extract_xml_hashes(
        self, comp_elem: ET.Element, ns: str
    ) -> dict[str, str]:
        hashes: dict[str, str] = {}
        for hash_elem in comp_elem.findall(f".//{ns}hash"):
            alg = hash_elem.get("alg", "")
            if alg and hash_elem.text:
                hashes[alg] = hash_elem.text
        return hashes

    def _extract_dependencies_xml(
        self, root: ET.Element, ns: str
    ) -> list[NormalizedDependency]:
        deps_section = root.find(f"{ns}dependencies")
        if deps_section is None:
            return []

        dependencies: list[NormalizedDependency] = []
        for dep_elem in deps_section.findall(f"{ns}dependency"):
            dep_ref = dep_elem.get("ref", "")
            child_deps = dep_elem.findall(f"{ns}dependency")
            dep_to = [
                child.get("ref", "")
                for child in child_deps
                if child.get("ref", "")
            ]
            if dep_ref:
                dependencies.append(
                    {"from": dep_ref, "to": dep_to, "type": "direct"}
                )
        return dependencies

    def _populate_name_version_from_purl(
        self, comp_data: dict[str, Any]
    ) -> None:
        if comp_data["name"] or not str(comp_data["purl"]).startswith("pkg:"):
            return

        parts = str(comp_data["purl"]).split("/")
        if len(parts) <= 2:
            return

        name_version = parts[2].split("@")
        if len(name_version) == 2:
            comp_data["name"] = name_version[0]
            comp_data["version"] = name_version[1]

    def _find_xml_text(self, root: ET.Element, ns: str, tag: str) -> str:
        element = root.find(f".//{ns}{tag}")
        return (
            element.text or "" if element is not None and element.text else ""
        )

    def _extract_licenses(self, comp: dict[str, Any]) -> list[str]:
        """Extract licenses from CycloneDX component."""
        licenses = []
        if "licenses" in comp:
            for license_info in comp["licenses"]:
                license_data = license_info.get("license", {})
                license_name = (
                    license_data.get("id") or license_data.get("name") or ""
                )
                if license_name:
                    licenses.append(license_name)
        return licenses

    def _extract_dependencies_json(
        self, data: dict[str, Any]
    ) -> list[NormalizedDependency]:
        """Extract dependencies from CycloneDX JSON."""
        deps: list[NormalizedDependency] = []
        if "dependencies" in data:
            for dep in data["dependencies"]:
                dep_from = dep.get("ref", "")
                dep_to = []

                # Handle both "dependsOn" (older specs) and "dependencies" (newer specs)
                depends_on = dep.get("dependsOn", [])
                dependencies = dep.get("dependencies", [])

                if depends_on:
                    dep_to = depends_on
                elif dependencies:
                    dep_to = [
                        d.get("ref", "") for d in dependencies if d.get("ref")
                    ]

                # Only add if has meaningful data
                if dep_from:
                    deps.append(
                        {
                            "from": dep_from,
                            "to": dep_to
                            if dep_to
                            else [],  # Empty list for leaf nodes
                            "type": "direct",
                        }
                    )

        return deps

    def get_extensions(self) -> list[str]:
        return [".cdx", ".cdx.json", ".json", ".xml"]
