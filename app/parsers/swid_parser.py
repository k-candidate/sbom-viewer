import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from app.sbom_types import Component, Metadata, NormalizedSBOM

from .base_parser import BaseSBOMParser


class SWIDParser(BaseSBOMParser):
    """Parser for SWID (Software ID) tags in XML format."""

    def can_parse(
        self, file_path: str, content: bytes, content_str: str
    ) -> bool:
        """Detect SWID by extension and XML root element."""
        file_ext = Path(file_path).suffix.lower()

        if file_ext in [".swidtag", ".xml"]:
            # SWID markers - BOTH 2015 and 2.2 schemas
            swid_markers = [
                "<SoftwareIdentity",
                "<swid:software_identification_tag",
                'xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd',  # 2015 schema (my sample)
                'xmlns:swid="http://standards.iso.org/iso/19770/-2/2009/schema.xsd',  # 2009 schema
                'xmlns:swid="http://standards.iso.org/iso/19770/-2/2/swid',  # 2.2 schema
                "tagId=",
                'xmlns="http://standards.iso.org/iso/19770/-2/2/swid',
            ]
            return any(marker in content_str for marker in swid_markers)

        return False

    def parse(
        self, file_path: str, content: bytes, content_str: str
    ) -> NormalizedSBOM:
        """Parse SWID XML into normalized structure."""
        try:
            root = ET.fromstring(content_str)
            namespaces = self._namespaces()
            software_identity = self._find_software_identity(root, namespaces)
            metadata = self._build_metadata(software_identity, namespaces)
            components = self._extract_components(
                software_identity, metadata, namespaces
            )
            return self._build_document(metadata, components, [])

        except ET.ParseError:
            return self._parse_legacy_text_swid(content_str)

    def _extract_licenses(
        self, software_identity: Any, namespaces: dict[str, str]
    ) -> list[str]:
        """Extract licenses from SWID SoftwareIdentity."""
        licenses: list[str] = []
        for prefix in ["swid", "swid22", "swid2009"]:
            for license_elem in software_identity.findall(
                f".//{prefix}:License", namespaces
            ):
                text = self._find_text(license_elem, "Text", namespaces)
                licenses.append(text or "Unknown")
        return licenses

    def _namespaces(self) -> dict[str, str]:
        return {
            "swid": "http://standards.iso.org/iso/19770/-2/2015/schema.xsd",
            "swid22": "http://standards.iso.org/iso/19770/-2/2/swid",
            "swid2009": "http://standards.iso.org/iso/19770/-2/2009/schema.xsd",
        }

    def _extract_components(
        self,
        software_identity: ET.Element,
        metadata: Metadata,
        namespaces: dict[str, str],
    ) -> list[Component]:
        components = [
            self._normalize_component(
                {
                    "name": metadata["name"],
                    "version": metadata["version"],
                    "purl": self._get_purl(software_identity, namespaces),
                    "type": "application",
                    "supplier": metadata["supplier"],
                    "description": software_identity.get("summary", ""),
                    "licenses": self._extract_licenses(
                        software_identity, namespaces
                    ),
                    "hashes": self._extract_hashes(
                        software_identity, namespaces
                    ),
                }
            )
        ]
        components.extend(
            self._extract_payload_components(
                software_identity, metadata, namespaces
            )
        )
        return components

    def _extract_hashes(
        self, software_identity: ET.Element, namespaces: dict[str, str]
    ) -> dict[str, str]:
        hashes: dict[str, str] = {}
        for prefix in ["swid", "swid22", "swid2009"]:
            for hash_elem in software_identity.findall(
                f".//{prefix}:Hash", namespaces
            ):
                hashes[hash_elem.get("algorithm", "unknown")] = (
                    hash_elem.text or ""
                )
        return hashes

    def _extract_payload_components(
        self,
        software_identity: ET.Element,
        metadata: Metadata,
        namespaces: dict[str, str],
    ) -> list[Component]:
        for prefix in ["swid", "swid22", "swid2009"]:
            payload = software_identity.find(
                f".//{prefix}:Payload", namespaces
            )
            if payload is None:
                continue

            return [
                self._normalize_component(
                    {
                        "name": file_elem.get("name", ""),
                        "version": "",
                        "purl": "",
                        "type": "file",
                        "supplier": metadata["supplier"],
                        "description": file_elem.get("description", ""),
                    }
                )
                for file_elem in payload.findall(
                    f".//{prefix}:File", namespaces
                )
            ]

        return []

    def get_extensions(self) -> list[str]:
        return [".swidtag", ".xml"] + super().get_extensions()

    def _parse_legacy_text_swid(self, content_str: str) -> NormalizedSBOM:
        """Best-effort fallback for malformed legacy SWID XML samples."""
        metadata = self._normalize_metadata(
            {
                "name": self._search_text(
                    content_str,
                    r"<swid:product_title[^>]*>(.*?)</swid:product_title>",
                ),
                "version": self._search_text(
                    content_str,
                    (
                        r"<swid:product_version[^>]*>.*?<swid:name>(.*?)"
                        r"</swid:name>.*?</swid:product_version>"
                    ),
                ),
                "creation_date": "",
                "supplier": self._search_text(
                    content_str,
                    (
                        r"<swid:software_creator>.*?<swid:name[^>]*>(.*?)"
                        r"</swid:name>.*?</swid:software_creator>"
                    ),
                ),
                "spec_version": "SWID",
            }
        )
        unique_id = self._search_text(
            content_str, r"<swid:unique_id[^>]*>(.*?)</swid:unique_id>"
        )
        description = self._search_text(
            content_str,
            r"<fs:original_arp_display_name[^>]*>(.*?)</fs:original_arp_display_name>",
        )

        if not metadata["name"]:
            raise ValueError("Invalid SWID XML format")

        component = self._normalize_component(
            {
                "name": metadata["name"],
                "version": metadata["version"],
                "licenses": [],
                "purl": unique_id,
                "type": "application",
                "supplier": metadata["supplier"],
                "hashes": {},
                "description": description,
            }
        )

        return self._build_document(metadata, [component], [])

    def _find_software_identity(
        self, root: ET.Element, namespaces: dict[str, str]
    ) -> ET.Element:
        local_name = self._local_name(root.tag)
        if local_name in {"SoftwareIdentity", "software_identification_tag"}:
            return root

        for prefix in namespaces:
            candidate = root.find(f"./{prefix}:SoftwareIdentity", namespaces)
            if candidate is not None:
                return candidate

        candidate = root.find(".//SoftwareIdentity")
        if candidate is not None:
            return candidate

        raise ValueError("No SoftwareIdentity element found")

    def _build_metadata(
        self, software_identity: ET.Element, namespaces: dict[str, str]
    ) -> Metadata:
        metadata = self._normalize_metadata(
            {
                "name": software_identity.get("name", ""),
                "version": software_identity.get("version", ""),
                "creation_date": software_identity.get("creation_date", ""),
                "supplier": "",
                "spec_version": "SWID",
            }
        )

        if not metadata["name"]:
            metadata["name"] = (
                self._find_text(software_identity, "product_title", namespaces)
                or ""
            )

        if not metadata["version"]:
            metadata["version"] = (
                self._find_text(
                    software_identity, "product_version/name", namespaces
                )
                or ""
            )

        entity_name = self._extract_supplier(software_identity, namespaces)
        if entity_name:
            metadata["supplier"] = entity_name

        return metadata

    def _extract_supplier(
        self, software_identity: ET.Element, namespaces: dict[str, str]
    ) -> str:
        for prefix in ["swid", "swid22"]:
            entity = software_identity.find(f".//{prefix}:Entity", namespaces)
            if entity is not None:
                return entity.get("name", "")

        creator_name = self._find_text(
            software_identity, "software_creator/name", namespaces
        )
        if creator_name:
            return creator_name

        entity = software_identity.find(".//Entity")
        if entity is not None:
            return entity.get("name", "")

        return ""

    def _get_purl(
        self, software_identity: ET.Element, namespaces: dict[str, str]
    ) -> str:
        return software_identity.get("tagId", "") or (
            self._find_text(
                software_identity, "software_id/unique_id", namespaces
            )
            or ""
        )

    def _find_text(
        self, root: ET.Element, path: str, namespaces: dict[str, str]
    ) -> str | None:
        path_parts = path.split("/")
        for prefix in ["swid", "swid22", "swid2009"]:
            namespaced_path = "/".join(
                f"{prefix}:{part}" for part in path_parts
            )
            element = root.find(f".//{namespaced_path}", namespaces)
            if element is not None and element.text:
                return element.text.strip()

        element = root.find(f".//{path}")
        if element is not None and element.text:
            return element.text.strip()

        return None

    @staticmethod
    def _local_name(tag: str) -> str:
        return tag.split("}", 1)[-1]

    @staticmethod
    def _search_text(content: str, pattern: str) -> str:
        match = re.search(pattern, content, re.DOTALL)
        return match.group(1).strip() if match else ""
