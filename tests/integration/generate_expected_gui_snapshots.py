import json
import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tests.support import (
    EXPECTED_GUI_DIR,
    expected_gui_snapshot_path,
    fixture_relative_path,
    iter_sbom_fixtures,
)
from app.models import SBOMModel
from app.parsers import detect_and_parse
from app.presentation import SBOMFormatter


def build_gui_snapshot(fixture_path: Path) -> dict[str, object]:
    model = SBOMModel()
    formatter = SBOMFormatter()
    model.load_from_parsed(detect_and_parse(str(fixture_path)))
    return {
        "fixture": str(fixture_relative_path(fixture_path)),
        "metadata": model.get_metadata(),
        "component_rows": [
            list(row) for row in formatter.component_rows(model.get_components())
        ],
        "dependency_rows": [
            list(row)
            for row in formatter.dependency_rows(model.get_dependencies())
        ],
    }


def main() -> None:
    if EXPECTED_GUI_DIR.exists():
        shutil.rmtree(EXPECTED_GUI_DIR)
    EXPECTED_GUI_DIR.mkdir(parents=True, exist_ok=True)

    for fixture_path in iter_sbom_fixtures():
        output_path = expected_gui_snapshot_path(fixture_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(build_gui_snapshot(fixture_path), indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
