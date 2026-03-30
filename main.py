import argparse
import json
from pathlib import Path

from app.presenter import SBOMPresenter
from app.view import MainView, disable_error_dialogs_for_testing


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Launch the SBOM Viewer app.")
    parser.add_argument(
        "--file",
        dest="file_path",
        help="Optional SBOM file to load on startup.",
    )
    parser.add_argument(
        "--dump-state",
        dest="dump_state_path",
        help="Optional JSON path used by automated E2E tests to dump visible state.",
    )
    parser.add_argument(
        "--exit-after-load-ms",
        dest="exit_after_load_ms",
        type=int,
        default=250,
        help="Delay before dumping state and exiting when --dump-state is used.",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)

    if args.dump_state_path:
        disable_error_dialogs_for_testing()

    presenter = SBOMPresenter()
    app = MainView(presenter)
    presenter.attach_view(app)

    if args.file_path:
        app.after(0, lambda: presenter.load_sbom(args.file_path))

    if args.dump_state_path:
        dump_path = Path(args.dump_state_path)

        def dump_and_close() -> None:
            dump_path.write_text(
                json.dumps(app.snapshot_state(), indent=2),
                encoding="utf-8",
            )
            app.destroy()

        app.after(args.exit_after_load_ms, dump_and_close)

    app.mainloop()


if __name__ == "__main__":
    main()
