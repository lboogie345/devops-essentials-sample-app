#!/usr/bin/env python3
"""Package the baseline for transfer to another GitHub instance.

Built for a cross-domain upload, which has requirements a `git archive` does
not meet:

  * **Integrity.** A SHA256SUMS file plus a per-file inventory, so the receiving
    side can prove what arrived is what was sent. A zip with no manifest is an
    unverifiable blob.
  * **Provenance.** The source commit, branch and build time are recorded inside
    the archive, because once it leaves this repository the git history does not
    travel with it.
  * **No secrets, no junk.** Scans for credential-shaped content and refuses to
    build if it finds any. Excludes .git, caches, evidence and build output.
  * **Reproducibility.** Fixed entry timestamps, sorted entries, and a build
    time taken from the source commit rather than the wall clock, so the same
    commit produces a byte-identical archive. A hash that changes between two
    builds of identical content cannot be used as evidence of anything - the
    receiving side could not tell a re-package from a tamper.
    Override with SOURCE_DATE_EPOCH if your process requires it.

  python scripts/package_release.py --output dist/
  python scripts/package_release.py --verify dist/stig-rhel8-cat2-<sha>.zip
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
import zipfile
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

# Everything the receiving repository needs, and nothing it does not.
INCLUDE = [
    "ansible",
    "aap",
    "scripts",
    "docs",
    ".github",
    ".ansible-lint",
    ".yamllint",
    "ruff.toml",
    "pytest.ini",
    "README.md",
]

EXCLUDE_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "collections",
    "evidence",
    "dist",
    ".gradle",
}
EXCLUDE_SUFFIXES = {".pyc", ".pyo", ".retry", ".log"}

# Credential-shaped content. A false positive here costs a minute; a private key
# crossing a domain boundary costs considerably more.
SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----"), "private key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
    (re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "GitHub personal access token"),
    (re.compile(r"\$ANSIBLE_VAULT;"), "inline Ansible vault payload"),
    (
        re.compile(
            r"(?i)^\s*(?!#)[A-Za-z_]*(password|passwd|secret|token)\s*[:=]\s*['\"]?[^'\"\s{#]{8,}"
        ),
        "hardcoded credential",
    ),
]
# Lines that legitimately mention these words while defining nothing: credential
# SHELLS in the AAP config, environment lookups, CI secret references, Jinja
# expressions, and this file's own detector definitions.
SECRET_ALLOW = re.compile(
    r"(become_password|ssh_key_data|CONTROLLER_OAUTH_TOKEN|ANSIBLE_VAULT_PASSWORD_FILE"
    r"|secrets\.|lookup\('env'|vault-pass|password_file|\{\{|<|survey|type: text"
    r"|re\.compile\(|SECRET_)"
)

TEXT_SUFFIXES = {".yml", ".yaml", ".py", ".md", ".cfg", ".txt", ".json", ".sh", ".j2", ""}


class PackagingError(Exception):
    """Refuse to build rather than ship something wrong."""


def git(*args: str) -> str:
    try:
        return subprocess.run(
            ["git", *args], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""


def collect(root: Path) -> list[Path]:
    files: list[Path] = []
    for name in INCLUDE:
        target = root / name
        if not target.exists():
            continue
        if target.is_file():
            files.append(target)
            continue
        for path in target.rglob("*"):
            if not path.is_file():
                continue
            if EXCLUDE_DIRS & set(path.relative_to(root).parts):
                continue
            if path.suffix in EXCLUDE_SUFFIXES:
                continue
            files.append(path)
    return sorted(files, key=lambda p: p.relative_to(root).as_posix())


def scan_for_secrets(root: Path, files: Sequence[Path]) -> list[str]:
    findings: list[str] = []
    for path in files:
        if path.suffix not in TEXT_SUFFIXES:
            continue
        try:
            body = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        rel = path.relative_to(root).as_posix()
        for number, line in enumerate(body.splitlines(), start=1):
            if line.lstrip().startswith("#") or SECRET_ALLOW.search(line):
                continue
            for pattern, label in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(f"{rel}:{number}: possible {label}")
    return findings


def build_manifest(root: Path, files: Sequence[Path], meta: dict[str, str]) -> tuple[str, str]:
    sums: list[str] = []
    inventory: list[str] = []
    for path in files:
        rel = path.relative_to(root).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        sums.append(f"{digest}  {rel}")
        inventory.append(f"{path.stat().st_size:>10}  {rel}")

    header = (
        [
            "RHEL 8 STIG CAT II baseline - transfer manifest",
            "=" * 60,
            "",
        ]
        + [f"{k:<18} {v}" for k, v in meta.items()]
        + [
            "",
            f"{'files':<18} {len(files)}",
            "",
            "Verify after transfer:",
            "    sha256sum -c SHA256SUMS",
            "",
            "File inventory (bytes, path):",
            "",
        ]
    )
    return "\n".join(sums) + "\n", "\n".join(header + inventory) + "\n"


def package(root: Path, out_dir: Path, name: str | None) -> Path:
    files = collect(root)
    if not files:
        raise PackagingError(f"nothing to package under {root}")

    secrets = scan_for_secrets(root, files)
    if secrets:
        raise PackagingError(
            "refusing to build; credential-shaped content found:\n  " + "\n  ".join(secrets)
        )

    sha = git("rev-parse", "HEAD") or "unknown"
    # Deterministic: the commit's own date, not the wall clock. Two builds of
    # one commit must be byte-identical or the checksum proves nothing.
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch and epoch.isdigit():
        built = datetime.fromtimestamp(int(epoch), tz=timezone.utc)
    else:
        commit_date = git("show", "-s", "--format=%cI", "HEAD")
        built = (
            datetime.fromisoformat(commit_date).astimezone(timezone.utc)
            if commit_date
            else datetime.now(timezone.utc)
        )
    meta = {
        "source commit": sha,
        "source branch": git("rev-parse", "--abbrev-ref", "HEAD") or "unknown",
        "built from commit dated (UTC)": built.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "benchmark": "RHEL 8 STIG V2R8 (2026-07-01), CAT II",
        "classification": "UNCLASSIFIED",
    }
    sums, manifest = build_manifest(root, files, meta)

    out_dir.mkdir(parents=True, exist_ok=True)
    archive = out_dir / (name or f"stig-rhel8-cat2-{sha[:12]}.zip")

    # Fixed timestamp: the same commit must produce the same bytes, or the hash
    # is evidence of nothing.
    fixed = (1980, 1, 1, 0, 0, 0)
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in files:
            rel = path.relative_to(root).as_posix()
            info = zipfile.ZipInfo(rel, date_time=fixed)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (path.stat().st_mode & 0xFFFF) << 16
            zf.writestr(info, path.read_bytes())
        for rel, body in (("SHA256SUMS", sums), ("TRANSFER-MANIFEST.txt", manifest)):
            info = zipfile.ZipInfo(rel, date_time=fixed)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, body)

    return archive


def verify(archive: Path) -> int:
    with zipfile.ZipFile(archive) as zf:
        names = set(zf.namelist())
        if "SHA256SUMS" not in names:
            sys.stderr.write(f"{archive}: no SHA256SUMS; cannot verify\n")
            return 1
        bad: list[str] = []
        checked = 0
        for line in zf.read("SHA256SUMS").decode().splitlines():
            expected, _, rel = line.partition("  ")
            if rel not in names:
                bad.append(f"missing: {rel}")
                continue
            actual = hashlib.sha256(zf.read(rel)).hexdigest()
            checked += 1
            if actual != expected:
                bad.append(f"checksum mismatch: {rel}")
        print(zf.read("TRANSFER-MANIFEST.txt").decode().split("File inventory")[0].strip())
        if bad:
            sys.stderr.write("\n".join(bad) + "\n")
            return 1
        print(f"\nOK: {checked} file(s) verified against SHA256SUMS.")
    return 0


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="package-release",
        description="Package the STIG baseline for transfer to another GitHub instance.",
    )
    parser.add_argument("--root", type=Path, default=Path())
    parser.add_argument("--output", type=Path, default=Path("dist"))
    parser.add_argument("--name", help="Archive filename (default: stig-rhel8-cat2-<sha>.zip).")
    parser.add_argument("--verify", type=Path, help="Verify an existing archive and exit.")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.verify:
        return verify(args.verify)
    try:
        archive = package(args.root.resolve(), args.output, args.name)
    except PackagingError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    size = archive.stat().st_size
    print(f"Wrote {archive} ({size / 1024:.0f} KiB)")
    print(f"Verify with: python scripts/package_release.py --verify {archive}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
