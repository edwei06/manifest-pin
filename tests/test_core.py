"""Exercise real binary payloads, relocation, strict checks, and malformed baselines."""
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from manifest_pin.cli import main
from manifest_pin.core import CHUNK_BYTES, ManifestError, create_manifest, load_manifest, verify_manifest


class Fixture:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "payload"
        self.root.mkdir()
        self.write("a.txt", b"alpha")

    def write(self, relative, data):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

class ManifestTests(Fixture, unittest.TestCase):
    def test_known_digest_empty_binary_and_unicode_paths(self):
        self.write("empty.bin", b"")
        self.write("資料/with space.bin", bytes(range(256)))
        document = create_manifest(self.root)
        self.assertEqual(document["files"][0]["sha256"], hashlib.sha256(b"alpha").hexdigest())
        self.assertTrue(verify_manifest(self.root, document, strict=True)["ok"])
        self.assertEqual(len(document["files"]), 3)

    def test_streamed_large_file_digest(self):
        data = b"z" * (2 * CHUNK_BYTES + 19)
        self.write("large.bin", data)
        record = next(record for record in create_manifest(self.root)["files"] if record["path"] == "large.bin")
        self.assertEqual(record["size"], len(data))
        self.assertEqual(record["sha256"], hashlib.sha256(data).hexdigest())

    def test_manifest_is_deterministic_and_paths_relative(self):
        self.write("nested/b.txt", b"beta")
        first, second = create_manifest(self.root), create_manifest(self.root)
        self.assertEqual(first, second)
        self.assertNotIn(str(self.root), json.dumps(first))

    def test_payload_can_move_without_regenerating_baseline(self):
        document = create_manifest(self.root)
        moved = Path(self.temp.name) / "moved"
        shutil.copytree(self.root, moved)
        self.assertTrue(verify_manifest(moved, document, strict=True)["ok"])

    def test_missing_and_same_size_content_changes(self):
        self.write("b.txt", b"beta")
        document = create_manifest(self.root)
        (self.root / "a.txt").write_bytes(b"other")
        (self.root / "b.txt").unlink()
        report = verify_manifest(self.root, document)
        self.assertEqual(report["issues"], [{"path": "a.txt", "code": "changed"},
                                            {"path": "b.txt", "code": "missing"}])

    def test_new_files_are_findings_only_in_strict_mode(self):
        document = create_manifest(self.root)
        self.write("new.txt", b"new")
        self.assertTrue(verify_manifest(self.root, document)["ok"])
        self.assertEqual(verify_manifest(self.root, document, strict=True)["issues"][0]["code"], "unexpected")

    def test_exclusions_prune_directories_and_persist(self):
        self.write("cache/ignored.bin", b"skip")
        self.write(".git/config", b"skip automatically")
        document = create_manifest(self.root, excludes=["cache", "*.tmp"])
        self.write("new.tmp", b"skip")
        self.assertEqual(len(document["files"]), 1)
        self.assertTrue(verify_manifest(self.root, document, strict=True)["ok"])

    def test_counts_remain_complete_with_capped_issues(self):
        document = create_manifest(self.root)
        for index in range(5):
            self.write(f"extra{index}.bin", b"extra")
        report = verify_manifest(self.root, document, strict=True, max_issues=1)
        self.assertEqual(report["issues_total"], 5)
        self.assertEqual(len(report["issues"]), 1)
        self.assertTrue(report["issues_truncated"])

    def test_file_limit_and_empty_selection_fail(self):
        self.write("b.txt", b"beta")
        with self.assertRaises(ManifestError):
            create_manifest(self.root, max_files=1)
        with self.assertRaises(ManifestError):
            create_manifest(self.root, excludes=["*"])

    def test_symlink_files_and_directory_components_are_not_followed(self):
        with tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / "secret.txt"
            target.write_bytes(b"outside")
            try:
                (self.root / "link.txt").symlink_to(target)
                (self.root / "linked-dir").symlink_to(Path(outside), target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("Host does not permit symlink creation")
            with self.assertRaises(ManifestError):
                create_manifest(self.root)
            document = create_manifest(self.root, excludes=["link.txt", "linked-dir"])
            self.assertEqual(len(document["files"]), 1)
            record = document["files"][0].copy()
            record["path"] = "linked-dir/secret.txt"
            document["files"] = [record]
            report = verify_manifest(self.root, document)
            self.assertEqual(report["issues"][0]["code"], "unsupported_or_unstable")

    def test_duplicate_json_members_and_nonfinite_values_fail(self):
        for text in ['{"format":"x","format":"y"}', '{"value": NaN}']:
            with self.assertRaises(ManifestError):
                load_manifest(text)

    def test_invalid_paths_are_rejected_before_file_access(self):
        baseline = create_manifest(self.root)
        for relative in ["../a.txt", "/tmp/a", "C:/a.txt", "a//b", "a/./b", ".git/config",
                         "folder\\a", "a:stream", "bad\nname"]:
            document = json.loads(json.dumps(baseline))
            document["files"][0]["path"] = relative
            with self.assertRaises(ManifestError, msg=relative):
                load_manifest(json.dumps(document))

    def test_duplicate_paths_wrong_sizes_hashes_and_algorithm_fail(self):
        baseline = create_manifest(self.root)
        mutations = []
        duplicate = json.loads(json.dumps(baseline))
        duplicate["files"].append(duplicate["files"][0])
        mutations.append(duplicate)
        for field, value in [("size", True), ("size", -1), ("sha256", "ABC"), ("sha256", "0" * 63)]:
            document = json.loads(json.dumps(baseline))
            document["files"][0][field] = value
            mutations.append(document)
        document = json.loads(json.dumps(baseline))
        document["algorithm"] = "md5"
        mutations.append(document)
        for document in mutations:
            with self.assertRaises(ManifestError):
                load_manifest(json.dumps(document))

    def test_listed_file_cannot_be_excluded(self):
        document = create_manifest(self.root)
        document["excludes"] = ["a.txt"]
        with self.assertRaises(ManifestError):
            load_manifest(json.dumps(document))

    def test_unstable_fingerprint_is_reported_as_finding(self):
        document = create_manifest(self.root)
        with patch("manifest_pin.core.fingerprint", side_effect=ManifestError("unstable")):
            report = verify_manifest(self.root, document)
        self.assertFalse(report["ok"])
        self.assertEqual(report["issues_total"], 1)


class CliTests(Fixture, unittest.TestCase):
    def call(self, *args):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            status = main([str(arg) for arg in args])
        return status, output.getvalue(), errors.getvalue()

    def test_create_inside_root_excludes_itself_and_strict_verify_passes(self):
        baseline = self.root / "manifest.json"
        self.assertEqual(self.call("create", self.root, baseline)[0], 0)
        document = json.loads(baseline.read_text(encoding="utf-8"))
        self.assertEqual(document["excludes"], ["manifest.json"])
        status, output, _ = self.call("verify", self.root, baseline, "--strict", "--format", "json")
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output)["files_matched"], 1)

    def test_existing_destination_and_payload_are_preserved(self):
        baseline = self.root / "manifest.json"
        self.call("create", self.root, baseline)
        previous = baseline.read_bytes()
        self.assertEqual(self.call("create", self.root, baseline)[0], 2)
        self.assertEqual(baseline.read_bytes(), previous)
        self.assertEqual((self.root / "a.txt").read_bytes(), b"alpha")

    def test_cli_findings_and_manifest_byte_limit(self):
        baseline = self.root / "manifest.json"
        self.call("create", self.root, baseline)
        (self.root / "a.txt").unlink()
        self.assertEqual(self.call("verify", self.root, baseline)[0], 1)
        self.assertEqual(self.call("verify", self.root, baseline, "--max-manifest-bytes", "2")[0], 2)


if __name__ == "__main__":
    unittest.main()
