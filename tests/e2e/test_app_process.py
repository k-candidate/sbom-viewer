import json
import os
import subprocess
import sys
from pathlib import Path

from tests.support import FIXTURES_DIR, PROJECT_ROOT


def run_app_and_capture_state(
    tmp_path: Path, *extra_args: str, timeout: float = 10.0
) -> dict[str, object]:
    state_path = tmp_path / "app-state.json"
    env = os.environ.copy()
    env.setdefault("PYTHONPATH", str(PROJECT_ROOT))

    command = [
        sys.executable,
        str(PROJECT_ROOT / "main.py"),
        *extra_args,
        "--dump-state",
        str(state_path),
        "--exit-after-load-ms",
        "300",
    ]

    completed = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    assert state_path.exists()
    return json.loads(state_path.read_text(encoding="utf-8"))


def test_main_process_loads_fixture_and_renders_state(tmp_path: Path) -> None:
    fixture_path = FIXTURES_DIR / "cyclonedx" / "cdx-1.5.json"

    state = run_app_and_capture_state(tmp_path, "--file", str(fixture_path))

    assert state["status"] == "Loaded SBOM: 1 components"
    assert ["six", "1.16.0", "MIT", "pkg:pypi/six@1.16.0"] in state["components"]
    assert ["root-component", "six==1.16.0", "direct"] in state["dependencies"]
    assert "name: editable-self" in state["metadata_text"]


def test_main_process_captures_error_state_for_missing_file(tmp_path: Path) -> None:
    missing_path = tmp_path / "missing.json"

    state = run_app_and_capture_state(tmp_path, "--file", str(missing_path))

    assert state["status"] == "Load failed"
    assert state["components"] == []
    assert state["dependencies"] == []
