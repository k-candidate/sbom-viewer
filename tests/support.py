import json
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent.parent
TESTS_ROOT = PROJECT_ROOT / "tests"
FIXTURES_DIR = TESTS_ROOT / "fixtures" / "sboms"
EXPECTED_GUI_DIR = TESTS_ROOT / "integration" / "expected" / "gui"

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def iter_sbom_fixtures() -> list[Path]:
    return sorted(path for path in FIXTURES_DIR.rglob("*") if path.is_file())


def fixture_relative_path(path: Path) -> Path:
    return path.relative_to(FIXTURES_DIR)


def expected_gui_snapshot_path(path: Path) -> Path:
    relative_path = fixture_relative_path(path)
    return (
        EXPECTED_GUI_DIR
        / relative_path.parent
        / f"{relative_path.name}.expected.json"
    )


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))
