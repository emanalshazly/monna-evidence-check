"""Usage: python -m monna_evidence_check MANIFEST --evidence-root DIRECTORY."""
import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .checker import InputError, check_manifest, load_manifest, render_markdown


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(3, "Input error: " + message + "\n")


def main(argv=None):
    parser = Parser(description="Check evaluation record structure and local evidence bindings; not claim truth.")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)
    try:
        report = check_manifest(load_manifest(args.manifest), args.evidence_root)
    except (InputError, OSError, RecursionError) as exc:
        # Do not leak host paths or untrusted input in error output.
        message = str(exc) if isinstance(exc, InputError) else "Cannot access the selected input."
        print(json.dumps({"check_status": "INPUT_ERROR", "error": message}), file=sys.stderr)
        return 3
    text = json.dumps(report, ensure_ascii=True, indent=2) + "\n" if args.format == "json" else render_markdown(report)
    try:
        sys.stdout.write(text)
    except UnicodeEncodeError:
        sys.stdout.buffer.write(text.encode("utf-8"))
    except BrokenPipeError:
        return 3
    return {"PASS": 0, "FAIL": 1, "UNRESOLVED": 2}[report["check_status"]]


if __name__ == "__main__":
    raise SystemExit(main())
