from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURE = (
    PROJECT_ROOT
    / "tests"
    / "fixtures"
    / "sboms"
    / "cyclonedx"
    / "cdx-1.5.json"
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a smoke test against a PyInstaller-built app."
    )
    parser.add_argument("--app-dir", required=True)
    parser.add_argument("--fixture", default=str(DEFAULT_FIXTURE))
    parser.add_argument("--timeout", type=float, default=15.0)
    return parser


def find_executable(app_dir: Path) -> Path:
    candidates = [
        app_dir / "sbom-viewer",
        app_dir / "sbom-viewer.exe",
        app_dir / "Contents" / "MacOS" / "sbom-viewer",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate

    for candidate in app_dir.rglob("sbom-viewer"):
        if candidate.is_file():
            return candidate

    for candidate in app_dir.rglob("sbom-viewer.exe"):
        if candidate.is_file():
            return candidate

    raise FileNotFoundError(f"Could not find packaged executable in {app_dir}")


def main() -> None:
    args = build_parser().parse_args()

    app_dir = Path(args.app_dir).resolve()
    fixture = Path(args.fixture).resolve()
    executable = find_executable(app_dir)
    state_path = app_dir / "smoke-test-state.json"

    completed = subprocess.run(
        [
            str(executable),
            "--file",
            str(fixture),
            "--dump-state",
            str(state_path),
            "--exit-after-load-ms",
            "500",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=args.timeout,
        check=False,
    )

    if completed.returncode != 0:
        raise SystemExit(completed.stderr or completed.stdout)

    if not state_path.exists():
        raise SystemExit(
            "Packaged app did not write the smoke-test state file"
        )

    state = json.loads(state_path.read_text(encoding="utf-8"))
    components = state.get("components", [])
    dependencies = state.get("dependencies", [])

    if state.get("status") != "Loaded SBOM: 1 components":
        raise SystemExit(
            f"Unexpected packaged app status: {state.get('status')!r}"
        )
    if ["six", "1.16.0", "MIT", "pkg:pypi/six@1.16.0"] not in components:
        raise SystemExit(
            "Packaged app did not render the expected component row"
        )
    if ["root-component", "six==1.16.0", "direct"] not in dependencies:
        raise SystemExit(
            "Packaged app did not render the expected dependency row"
        )

    print(f"Smoke test passed for {executable.name}")


if __name__ == "__main__":
    main()
