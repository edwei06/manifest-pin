"""Stream local files into deterministic, root-relative SHA-256 manifests."""
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import stat

FORMAT = "manifest-pin/v1"
MAX_FILES = 100000
CHUNK_BYTES = 1024 * 1024


class ManifestError(ValueError):
    """An input cannot be completely or safely evaluated."""


def normalize_path(value):
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        raise ManifestError("Manifest paths must be nonempty relative POSIX paths")
    if value.startswith("/") or any(part in {"", ".", "..", ".git"} for part in value.split("/")):
        raise ManifestError("Manifest paths cannot be absolute, traversing, or Git metadata")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ManifestError("Manifest paths cannot contain control characters")
    try:
        value.encode("utf-8")
    except UnicodeError as error:
        raise ManifestError("Manifest paths must be valid UTF-8") from error
    return value


def _root(root):
    root = Path(root).resolve()
    if not root.is_dir():
        raise ManifestError("Root must be an existing directory")
    return root


def excluded(relative, patterns):
    return any(fnmatch.fnmatchcase(relative, pattern) or
               fnmatch.fnmatchcase(relative + "/", pattern) for pattern in patterns)


def paths_under(root, patterns=(), *, max_files=MAX_FILES):
    """Yield file paths and symlinks without following directory symlinks."""
    count = 0

    def scan_error(error):
        raise ManifestError("Unable to scan the root directory") from error

    for directory, dirs, names in os.walk(root, followlinks=False, onerror=scan_error):
        parent = Path(directory)
        for name in sorted(dirs[:]):
            path = parent / name
            relative = path.relative_to(root).as_posix()
            if name == ".git" or excluded(relative, patterns):
                dirs.remove(name)
            elif path.is_symlink():
                dirs.remove(name)
                count += 1
                if count > max_files:
                    raise ManifestError("File count limit exceeded")
                yield relative
        dirs.sort()
        for name in sorted(names):
            path = parent / name
            relative = path.relative_to(root).as_posix()
            if name == ".git" or excluded(relative, patterns):
                continue
            normalize_path(relative)
            count += 1
            if count > max_files:
                raise ManifestError("File count limit exceeded")
            yield relative


def fingerprint(root, relative):
    relative = normalize_path(relative)
    current = root
    for part in relative.split("/"):
        current = current / part
        if current.is_symlink():
            raise ManifestError("Symlink paths are unsupported")
    resolved = current.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ManifestError("Path resolves outside the root") from error
    if not stat.S_ISREG(current.stat().st_mode):
        raise ManifestError("Only regular files can be hashed")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(current, flags)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ManifestError("Only regular files can be hashed")
        digest, size = hashlib.sha256(), 0
        while True:
            chunk = stream.read(CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
        after = os.fstat(stream.fileno())
    before_key = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    after_key = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    if before_key != after_key or size != after.st_size:
        raise ManifestError("File changed while being hashed; retry with a stable directory")
    return {"path": relative, "size": size, "sha256": digest.hexdigest()}


def create_manifest(root, *, excludes=(), max_files=MAX_FILES):
    root = _root(root)
    if max_files < 1 or any(not isinstance(pattern, str) for pattern in excludes):
        raise ManifestError("Invalid manifest limits or exclude patterns")
    patterns = sorted(set(excludes))
    records = []
    for relative in sorted(paths_under(root, patterns, max_files=max_files)):
        records.append(fingerprint(root, relative))
    if not records:
        raise ManifestError("No regular files selected")
    return {"format": FORMAT, "algorithm": "sha256", "excludes": patterns, "files": records}


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError("Duplicate JSON member")
        result[key] = value
    return result


def _constant(value):
    raise ManifestError("Nonfinite JSON constants are unsupported")


def load_manifest(text, *, max_files=MAX_FILES):
    try:
        document = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
    except (json.JSONDecodeError, RecursionError, ValueError) as error:
        raise ManifestError("Invalid JSON manifest") from error
    if not isinstance(document, dict) or set(document) != {"format", "algorithm", "excludes", "files"}:
        raise ManifestError("Unsupported manifest structure")
    if document["format"] != FORMAT or document["algorithm"] != "sha256":
        raise ManifestError("Unsupported manifest format or hash algorithm")
    patterns = document["excludes"]
    records = document["files"]
    if not isinstance(patterns, list) or any(not isinstance(pattern, str) for pattern in patterns):
        raise ManifestError("Exclude patterns must be strings")
    if not isinstance(records, list) or not records or len(records) > max_files:
        raise ManifestError("Manifest file count is empty or exceeds the limit")
    seen = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {"path", "size", "sha256"}:
            raise ManifestError("Unsupported file record")
        relative = normalize_path(record["path"])
        if relative in seen:
            raise ManifestError("Duplicate manifest path")
        seen.add(relative)
        if type(record["size"]) is not int or record["size"] < 0:
            raise ManifestError("File sizes must be nonnegative integers")
        if not isinstance(record["sha256"], str) or not re.fullmatch("[0-9a-f]{64}", record["sha256"]):
            raise ManifestError("Expected a lowercase SHA-256 hex digest")
        if excluded(relative, patterns):
            raise ManifestError("A listed file cannot also match an exclusion")
    return document


def verify_manifest(root, document, *, strict=False, skip=(), max_issues=100,
                    max_files=MAX_FILES):
    root = _root(root)
    if max_issues < 1 or max_files < 1:
        raise ManifestError("Limits must be positive")
    # Validate programmatic inputs with the same schema as file inputs.
    document = load_manifest(json.dumps(document), max_files=max_files)
    report = {"ok": True, "files_checked": 0, "files_matched": 0,
              "issues_total": 0, "issues_truncated": False, "issues": []}

    def issue(path, code):
        report["issues_total"] += 1
        if len(report["issues"]) < max_issues:
            report["issues"].append({"path": path, "code": code})

    known = {record["path"] for record in document["files"]}
    for expected in document["files"]:
        relative = expected["path"]
        report["files_checked"] += 1
        try:
            actual = fingerprint(root, relative)
        except FileNotFoundError:
            issue(relative, "missing")
            continue
        except ManifestError:
            issue(relative, "unsupported_or_unstable")
            continue
        if actual["size"] != expected["size"] or actual["sha256"] != expected["sha256"]:
            issue(relative, "changed")
        else:
            report["files_matched"] += 1
    if strict:
        for relative in sorted(paths_under(root, document["excludes"], max_files=max_files)):
            if relative not in known and relative not in skip:
                issue(relative, "unexpected")
    report["ok"] = report["issues_total"] == 0
    report["issues_truncated"] = report["issues_total"] > len(report["issues"])
    return report
