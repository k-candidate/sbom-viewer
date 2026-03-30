from pathlib import Path

from app.sbom_types import NormalizedSBOM

# Import all parsers
from .cyclonedx_parser import CycloneDXParser
from .spdx_parser import SPDXParser
from .swid_parser import SWIDParser

# Registry of all available parsers
PARSERS = [SPDXParser(), CycloneDXParser(), SWIDParser()]


def detect_and_parse(file_path: str) -> NormalizedSBOM:
    """
    Auto-detect SBOM format and parse into normalized structure.

    Args:
        file_path: Path to SBOM file

    Returns:
        Normalized SBOM dict

    Raises:
        ValueError: If format not recognized or parsing fails
    """
    path = Path(file_path)
    if not path.exists():
        raise ValueError(f"File not found: {file_path}")

    content = path.read_bytes()

    content_str = content.decode("utf-8", errors="ignore")

    # Try each parser in order
    for parser in PARSERS:
        if parser.can_parse(file_path, content, content_str):
            try:
                return parser.parse(file_path, content, content_str)
            except Exception as exc:
                raise ValueError(
                    f"Parser {parser.__class__.__name__} failed: {exc}"
                ) from exc

    raise ValueError(f"Unsupported SBOM format for {file_path}")


def get_supported_extensions() -> list[str]:
    """Get all supported file extensions."""
    exts = set()
    for parser in PARSERS:
        exts.update(parser.get_extensions())
    return sorted(exts)
