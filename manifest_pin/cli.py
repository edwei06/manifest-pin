"""Create a new baseline or verify one; never change payload files."""
import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .core import MAX_FILES, ManifestError, create_manifest, load_manifest, verify_manifest


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("Expected a positive integer")
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description="Portable SHA-256 file manifests for stable local folders.")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="Write a new JSON baseline")
    create.add_argument("root")
    create.add_argument("manifest")
    create.add_argument("--exclude", action="append", default=[], metavar="GLOB")
    create.add_argument("--max-files", type=positive, default=MAX_FILES)
    verify = commands.add_parser("verify", help="Compare payloads against a baseline")
    verify.add_argument("root")
    verify.add_argument("manifest")
    verify.add_argument("--strict", action="store_true", help="Also detect unexpected files")
    verify.add_argument("--max-files", type=positive, default=MAX_FILES)
    verify.add_argument("--max-issues", type=positive, default=100)
    verify.add_argument("--max-manifest-bytes", type=positive, default=16 * 1024 * 1024)
    verify.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    manifest = Path(args.manifest)
    try:
        try:
            relative = manifest.resolve().relative_to(root).as_posix()
        except ValueError:
            relative = None
        if args.command == "create":
            if manifest.exists():
                raise ManifestError("Manifest destination already exists; choose a new filename")
            excludes = list(args.exclude)
            if relative:
                excludes.append(relative)
            document = create_manifest(root, excludes=excludes, max_files=args.max_files)
            payload = json.dumps(document, indent=2, ensure_ascii=True) + "\n"
            with manifest.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(payload)
            print(f"{len(document['files'])} file(s) recorded")
            return 0
        with manifest.open("rb") as stream:
            payload = stream.read(args.max_manifest_bytes + 1)
        if len(payload) > args.max_manifest_bytes:
            raise ManifestError("Manifest byte limit exceeded")
        document = load_manifest(payload.decode("utf-8-sig"), max_files=args.max_files)
        report = verify_manifest(root, document, strict=args.strict,
                                 skip=[relative] if relative else [],
                                 max_issues=args.max_issues, max_files=args.max_files)
    except (ManifestError, OSError, UnicodeError, RuntimeError) as error:
        print(f"manifest-pin: {error}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(report, indent=2, ensure_ascii=True))
    else:
        for issue in report["issues"]:
            print(f"{issue['code']}: {issue['path']}")
        print(f"{report['files_matched']}/{report['files_checked']} known file(s) match; "
              f"{report['issues_total']} issue(s)")
        if report["issues_truncated"]:
            print("Issue samples capped; totals cover all selected files")
    return 0 if report["ok"] else 1
