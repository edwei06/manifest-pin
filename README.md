# manifest-pin

Verify a copied folder or release bundle with a small, portable SHA-256 baseline.

The manifest stores relative paths, byte sizes, and hashes in JSON. It has no
machine-specific root or generation timestamp, so the same baseline works after
moving the payload. Spaces and Unicode paths remain unambiguous.

Requires Python 3.10+. No runtime dependencies or network access.

## Quick start

~~~sh
python -m pip install .
manifest-pin create examples/payload baseline.json
manifest-pin verify examples/payload baseline.json --strict
~~~

Create a baseline after your data or build artifacts are stable. Transfer it
with the payload, then verify against the copied folder. `--strict` also reports
new files; default verification checks only known files.

Baselines are new files: creation never overwrites an existing destination.
If a baseline is inside the payload root, its own path is automatically excluded.
Git administrative files/directories named `.git` are always excluded.

## Example format

~~~json
{
  "format": "manifest-pin/v1",
  "algorithm": "sha256",
  "excludes": [],
  "files": [
    {"path": "notes.txt", "size": 5, "sha256": "<64 lowercase hex characters>"}
  ]
}
~~~

The displayed digest is illustrative; generate a real manifest with the CLI.
File entries are sorted. Empty selections, duplicate paths/members, malformed
hashes, unsupported formats, negative/bool sizes, absolute paths, traversal,
backslashes, colon paths, and control characters are rejected.

## Options

~~~sh
manifest-pin create data manifest-v2.json --exclude "cache" --exclude "*.tmp"
manifest-pin verify data manifest-v2.json --strict --format json --max-issues 20
~~~

Exclusions are case-sensitive globs over root-relative POSIX paths, stored in the
baseline. A matching directory is pruned. The file limit defaults to 100,000;
use `--max-files N` to change it. Manifest inputs are limited to 16 MiB by default
with `--max-manifest-bytes N`. Findings are capped at 100 samples by default,
while counts cover all selected files.

Exit 0 means creation/verification succeeded; 1 means verification findings;
2 means an input, scan, read, write, or manifest error prevented completion.

## Scope

Only regular files are hashed. Symlink files and path components are rejected;
directory symlinks are never traversed. File bytes are streamed in 1 MiB chunks.
A change in file size or stat metadata during reading is detected, but the tool
does not provide an atomic filesystem snapshot or defend against concurrent,
adversarial filesystem replacement. Use a stable directory.

Hashes compare bytes, not permissions, timestamps, empty directories, filesystem
attributes, or ownership. Paths retain their original case and Unicode spelling;
this is not a universal filesystem-portability checker.

A checksum baseline is not a signature or authenticity proof. Store or distribute
the baseline through a trusted channel; an attacker replacing both the data and
manifest can create a matching pair.

## Development

~~~sh
python -m unittest discover -s tests -v
~~~

Tests cover binary payloads, chunk boundaries, relocation, strict-mode additions,
malformed baselines, exclusions, symlinks, and unchanged payloads.
See [CONTRIBUTING.md](CONTRIBUTING.md) and [LICENSE](LICENSE).

Related work: [hashit](https://github.com/boyter/hashit).
The narrower interface uses a JSON baseline and Python's standard-library SHA-256.
Implementation and examples are independently authored.
