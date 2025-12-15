import json
import re
from pathlib import Path
from typing import Any, Optional

from app.sbom_types import (
    Component,
    Metadata,
    NormalizedDependency,
    NormalizedSBOM,
)

from .base_parser import BaseSBOMParser


class SPDXParser(BaseSBOMParser):
    """Parser for SPDX SBOM format (JSON and tag/value)."""

    def can_parse(
        self, file_path: str, content: bytes, content_str: str
    ) -> bool:
        """Detect SPDX format by extension and content markers (2.x + 3.0)."""
        file_ext = Path(file_path).suffix.lower()

        # File extension check
        if file_ext in [".spdx", ".spdx.json", ".json"]:
            # SPDX 2.x JSON: look for SPDXID or spdxVersion
            if (
                '"SPDXID"' in content_str
                or '"spdxVersion"' in content_str
                or '"name"' in content_str
                and '"packages"' in content_str
            ):
                return True

            # SPDX 3.0 JSON-LD: look for @context and SPDX markers
            if (
                '"@context"' in content_str
                and '"specVersion"' in content_str
                and (
                    '"SpdxDocument"' in content_str
                    or '"CreationInfo"' in content_str
                )
            ):
                return True

            # Tag/value SPDX: look for SPDXVersion line
            if re.search(
                r"^SPDXVersion:\s*SPDX-?\d+\.\d+", content_str, re.MULTILINE
            ):
                return True

        return False

    def parse(
        self, file_path: str, content: bytes, content_str: str
    ) -> NormalizedSBOM:
        """Parse SPDX into normalized structure."""
        file_ext = Path(file_path).suffix.lower()

        if file_ext == ".json" or '"spdxVersion"' in content_str:
            return self._parse_json_spdx(content_str)
        else:
            return self._parse_tagvalue_spdx(content_str)

    def _parse_json_spdx(self, content_str: str) -> NormalizedSBOM:
        """Parse SPDX JSON format (2.x and 3.0)."""
        try:
            data = json.loads(content_str)

            # SPDX 3.0 JSON-LD format
            if "@context" in data and "@graph" in data:
                return self._parse_spdx_v3(data)

            metadata = self._parse_spdx_v2_metadata(data)
            components, ref_lookup = self._parse_spdx_v2_components(data)
            dependencies = self._extract_dependencies_json(data, ref_lookup)

            return self._build_document(metadata, components, dependencies)

        except json.JSONDecodeError:
            raise ValueError("Invalid SPDX JSON format")

    def _parse_spdx_v3(self, data: dict[str, Any]) -> NormalizedSBOM:
        """Parse SPDX 3.0 JSON-LD format."""
        graph = data.get("@graph", [])

        metadata = self._parse_spdx_v3_metadata(graph)
        components, ref_lookup = self._parse_spdx_v3_components(graph)
        dependencies = self._extract_dependencies_v3(graph, ref_lookup)

        return self._build_document(metadata, components, dependencies)

    def _parse_tagvalue_spdx(self, content_str: str) -> NormalizedSBOM:
        """Parse SPDX tag/value format."""
        lines = content_str.splitlines()
        current_pkg: Optional[dict[str, Any]] = None
        current_spdx_id = ""
        components: list[Component] = []
        ref_lookup: dict[str, str] = {}
        dependencies: list[NormalizedDependency] = []
        metadata = self._normalize_metadata(
            {
                "name": "",
                "version": "",
                "creation_date": "",
                "supplier": "Unknown",
                "spec_version": "",
            }
        )

        for line in lines:
            if line.startswith("SPDXVersion:"):
                metadata["version"] = line.split(":", 1)[1].strip()
            elif line.startswith("DocumentName:"):
                metadata["name"] = line.split(":", 1)[1].strip()
            elif line.startswith("Created:"):
                metadata["creation_date"] = line.split(":", 1)[1].strip()
            elif line.startswith("PackageName:"):
                if current_pkg:
                    normalized_component = self._normalize_component(
                        current_pkg
                    )
                    components.append(normalized_component)
                    if current_spdx_id:
                        ref_lookup[current_spdx_id] = (
                            self._component_identifier(normalized_component)
                        )
                current_pkg = self._start_tagvalue_package(line)
                current_spdx_id = ""
            elif line.startswith("SPDXID:") and current_pkg is not None:
                current_spdx_id = line.split(":", 1)[1].strip()
            elif current_pkg:
                self._update_tagvalue_package(current_pkg, line)
            elif line.startswith("Relationship:"):
                dependency = self._parse_tagvalue_relationship(
                    line, ref_lookup
                )
                if dependency is not None:
                    dependencies.append(dependency)

        if current_pkg:
            normalized_component = self._normalize_component(current_pkg)
            components.append(normalized_component)
            if current_spdx_id:
                ref_lookup[current_spdx_id] = self._component_identifier(
                    normalized_component
                )

        metadata["spec_version"] = metadata.get("version", "")

        return self._build_document(metadata, components, dependencies)

    def _parse_spdx_v2_metadata(self, data: dict[str, Any]) -> Metadata:
        creation_info = data.get("creationInfo", {})
        return self._normalize_metadata(
            {
                "name": data.get("name", ""),
                "version": data.get("spdxVersion", ""),
                "creation_date": creation_info.get(
                    "created", data.get("created", "")
                ),
                "supplier": data.get("organization", data.get("creator", "")),
                "spec_version": data.get("spdxVersion", ""),
            }
        )

    def _parse_spdx_v2_components(
        self, data: dict[str, Any]
    ) -> tuple[list[Component], dict[str, str]]:
        components: list[Component] = []
        ref_lookup: dict[str, str] = {}

        for pkg in data.get("packages", []):
            component = self._normalize_component(
                {
                    "name": pkg.get("name", ""),
                    "version": pkg.get("versionInfo", ""),
                    "licenses": self._extract_licenses(pkg),
                    "purl": self._normalize_spdx_optional_text(
                        pkg.get("downloadLocation", "")
                    ),
                    "type": "package",
                    "supplier": self._normalize_spdx_optional_text(
                        pkg.get("supplier", "")
                    ),
                    "hashes": {
                        checksum.get("alg"): checksum.get("content")
                        for checksum in pkg.get("checksums", [])
                    },
                    "description": self._normalize_spdx_optional_text(
                        pkg.get("summary", "")
                    ),
                }
            )
            components.append(component)

            spdx_id = self._clean_text(pkg.get("SPDXID", ""))
            if spdx_id:
                ref_lookup[spdx_id] = self._component_identifier(component)

        return components, ref_lookup

    def _parse_spdx_v3_metadata(self, graph: list[dict[str, Any]]) -> Metadata:
        creation_info = next(
            (item for item in graph if item.get("type") == "CreationInfo"), {}
        )
        metadata = self._normalize_metadata(
            {
                "name": "",
                "version": creation_info.get("specVersion", "3.0"),
                "creation_date": creation_info.get("created", ""),
                "supplier": "",
                "spec_version": creation_info.get("specVersion", "3.0"),
            }
        )
        document = next(
            (item for item in graph if item.get("type") == "SpdxDocument"), {}
        )
        metadata["name"] = document.get("name", "")
        return metadata

    def _parse_spdx_v3_components(
        self, graph: list[dict[str, Any]]
    ) -> tuple[list[Component], dict[str, str]]:
        components: list[Component] = []
        ref_lookup: dict[str, str] = {}
        for item in graph:
            item_type = item.get("type", "")
            if item_type not in ["software_File", "software_Package"]:
                continue

            comp_data = {
                "name": item.get("name", ""),
                "version": "",
                "licenses": [],
                "purl": "",
                "type": item_type.split("_")[-1],
                "supplier": "",
                "description": item.get("comment", ""),
                "hashes": self._extract_v3_hashes(item),
            }
            component = self._normalize_component(comp_data)
            components.append(component)

            spdx_id = self._clean_text(item.get("spdxId", ""))
            if spdx_id:
                ref_lookup[spdx_id] = self._component_identifier(component)

        return components, ref_lookup

    def _extract_v3_hashes(self, item: dict[str, Any]) -> dict[str, str]:
        hashes: dict[str, str] = {}
        for hash_item in item.get("verifiedUsing", []):
            if isinstance(hash_item, dict) and "algorithm" in hash_item:
                hashes[hash_item["algorithm"]] = hash_item["hashValue"]
        return hashes

    def _extract_dependencies_v3(
        self, graph: list[dict[str, Any]], ref_lookup: dict[str, str]
    ) -> list[NormalizedDependency]:
        dependencies: list[NormalizedDependency] = []
        for item in graph:
            if item.get("type") != "Relationship":
                continue

            dependency = self._parse_v3_relationship(item, ref_lookup)
            if dependency is not None:
                dependencies.append(dependency)

        return dependencies

    def _parse_v3_relationship(
        self, relationship: dict[str, Any], ref_lookup: dict[str, str]
    ) -> NormalizedDependency | None:
        rel_type = self._clean_text(
            relationship.get("relationshipType", "")
        ).lower()
        if rel_type not in {"contains", "generates"}:
            return None

        dep_from = self._resolve_ref(
            self._clean_text(relationship.get("from", "")), ref_lookup
        )
        dep_to = self._normalize_string_list(
            [
                self._resolve_ref(target, ref_lookup)
                for target in relationship.get("to", [])
            ]
        )

        if not dep_from or not dep_to:
            return None

        return {"from": dep_from, "to": dep_to, "type": rel_type}

    def _start_tagvalue_package(
        self,
        line: str,
    ) -> dict[str, Any]:
        return {
            "name": line.split(":", 1)[1].strip(),
            "licenses": [],
        }

    def _update_tagvalue_package(
        self, current_pkg: dict[str, Any], line: str
    ) -> None:
        if line.startswith("PackageVersion:"):
            current_pkg["version"] = line.split(":", 1)[1].strip()
        elif line.startswith("PackageDownloadLocation:"):
            current_pkg["purl"] = self._normalize_spdx_optional_text(
                line.split(":", 1)[1].strip()
            )
        elif line.startswith("PackageLicenseConcluded:"):
            license_value = self._normalize_spdx_optional_text(
                line.split(":", 1)[1].strip()
            )
            if license_value:
                current_pkg["licenses"].append(license_value)
        elif line.startswith("PackageLicenseInfoFromFiles:"):
            license_value = self._normalize_spdx_optional_text(
                line.split(":", 1)[1].strip()
            )
            if license_value:
                current_pkg["licenses"].append(license_value)

    def _extract_licenses(self, pkg: dict[str, Any]) -> list[str]:
        """Extract licenses from SPDX package."""
        licenses = []
        if "licenseConcluded" in pkg:
            license_value = self._normalize_spdx_optional_text(
                pkg["licenseConcluded"]
            )
            if license_value:
                licenses.append(license_value)
        if "licenseInfoInFiles" in pkg:
            licenses.extend(
                license_value
                for license_value in (
                    self._normalize_spdx_optional_text(item)
                    for item in pkg["licenseInfoInFiles"]
                )
                if license_value
            )
        return licenses

    def _extract_dependencies_json(
        self, data: dict[str, Any], ref_lookup: dict[str, str]
    ) -> list[NormalizedDependency]:
        """Extract dependency-style relationships from SPDX JSON."""
        deps: list[NormalizedDependency] = []
        if "relationships" in data:
            for rel in data["relationships"]:
                dependency = self._parse_json_relationship(rel, ref_lookup)
                if dependency is not None:
                    deps.append(dependency)
        return deps

    def _parse_json_relationship(
        self, relationship: dict[str, Any], ref_lookup: dict[str, str]
    ) -> NormalizedDependency | None:
        rel_type = self._clean_text(
            relationship.get("relationshipType", "")
        ).upper()
        left_ref = self._clean_text(
            relationship.get("spdxElementRefA", "")
            or relationship.get("spdxElementId", "")
        )
        right_ref = self._clean_text(
            relationship.get("spdxElementRefB", "")
            or relationship.get("relatedSpdxElement", "")
        )

        return self._relationship_to_dependency(
            rel_type, left_ref, right_ref, ref_lookup
        )

    def _parse_tagvalue_relationship(
        self, line: str, ref_lookup: dict[str, str]
    ) -> NormalizedDependency | None:
        _, payload = line.split(":", 1)
        parts = payload.strip().split()
        if len(parts) != 3:
            return None

        left_ref, rel_type, right_ref = parts
        return self._relationship_to_dependency(
            rel_type.upper(), left_ref, right_ref, ref_lookup
        )

    def _relationship_to_dependency(
        self,
        rel_type: str,
        left_ref: str,
        right_ref: str,
        ref_lookup: dict[str, str],
    ) -> NormalizedDependency | None:
        dependency_type = self._spdx_dependency_type(rel_type)
        if dependency_type is None:
            return None

        if rel_type.endswith("_DEPENDENCY_OF") or rel_type == "DEPENDENCY_OF":
            dep_from = self._resolve_ref(right_ref, ref_lookup)
            dep_to = self._resolve_ref(left_ref, ref_lookup)
        else:
            dep_from = self._resolve_ref(left_ref, ref_lookup)
            dep_to = self._resolve_ref(right_ref, ref_lookup)

        if not dep_from or not dep_to:
            return None

        return {"from": dep_from, "to": [dep_to], "type": dependency_type}

    def _spdx_dependency_type(self, rel_type: str) -> str | None:
        direct_types = {"DEPENDS_ON", "DEPENDENCY_OF"}
        if rel_type in direct_types:
            return "direct"

        if rel_type.endswith("_DEPENDENCY_OF"):
            return rel_type.removesuffix("_DEPENDENCY_OF").lower()

        if rel_type.endswith("_DEPENDS_ON"):
            return rel_type.removesuffix("_DEPENDS_ON").lower()

        return None

    def _resolve_ref(self, spdx_ref: str, ref_lookup: dict[str, str]) -> str:
        return ref_lookup.get(spdx_ref, spdx_ref)

    def _component_identifier(self, component: Component) -> str:
        return component["name"] or component["purl"]

    def _normalize_spdx_optional_text(self, value: Any) -> str:
        cleaned = self._clean_text(value)
        if cleaned.upper() in {"NOASSERTION", "NONE"}:
            return ""
        return cleaned

    def get_extensions(self) -> list[str]:
        return [".spdx", ".spdx.json", ".json"]
