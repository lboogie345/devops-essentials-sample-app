"""Tests for the transfer packaging.

The archive is the artifact that crosses a domain boundary, so its properties
have to hold without anyone checking by hand: no secrets, no junk, verifiable
checksums, and a hash that means something.
"""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

from scripts import package_release as pkg

REPO = Path(__file__).resolve().parents[2]


def build(tmp_path: Path) -> Path:
    return pkg.package(REPO, tmp_path, "test.zip")


def test_archive_builds_and_self_verifies(tmp_path, capsys):
    archive = build(tmp_path)
    assert pkg.verify(archive) == 0
    assert "verified against SHA256SUMS" in capsys.readouterr().out


def test_two_builds_of_one_commit_are_byte_identical(tmp_path):
    a = pkg.package(REPO, tmp_path / "a", "x.zip")
    b = pkg.package(REPO, tmp_path / "b", "x.zip")
    # Otherwise the receiving side cannot tell a re-package from a tamper.
    assert hashlib.sha256(a.read_bytes()).hexdigest() == hashlib.sha256(b.read_bytes()).hexdigest()


def test_archive_excludes_git_and_caches(tmp_path):
    with zipfile.ZipFile(build(tmp_path)) as zf:
        names = zf.namelist()
    assert not any(n.startswith(".git/") for n in names)
    assert not any("__pycache__" in n for n in names)
    assert not any(n.endswith(".pyc") for n in names)
    assert not any(n.startswith("dist/") for n in names)


def test_archive_carries_everything_the_receiver_needs(tmp_path):
    with zipfile.ZipFile(build(tmp_path)) as zf:
        names = set(zf.namelist())
    for required in (
        "ansible/remediate.yml",
        "ansible/audit.yml",
        "ansible/report.yml",
        "ansible/controls/rhel8_cat2_controls.yml",
        "aap/configure.yml",
        "aap/controller/job_templates.yml",
        "aap/controller/category_audits.yml",
        "scripts/stig/report.py",
        "docs/CONTROL-REFERENCE.md",
        "docs/AAP-INTEGRATION.md",
        ".github/workflows/stig-validate.yml",
        "SHA256SUMS",
        "TRANSFER-MANIFEST.txt",
    ):
        assert required in names, f"missing from transfer archive: {required}"


def test_every_control_task_file_is_included(tmp_path):
    import yaml

    controls = yaml.safe_load(
        (REPO / "ansible/controls/rhel8_cat2_controls.yml").read_text(encoding="utf-8")
    )["controls"]
    with zipfile.ZipFile(build(tmp_path)) as zf:
        names = set(zf.namelist())
    tasks = {n for n in names if n.startswith("ansible/roles/rhel8_stig_cat2/tasks/")}
    # 29 controls, 27 include files (three sysctl controls share one).
    assert len(tasks) >= 27
    assert "ansible/roles/rhel8_stig_cat2/tasks/sysctl_network.yml" in names
    assert len(controls) == 29


def test_manifest_lists_provenance(tmp_path):
    with zipfile.ZipFile(build(tmp_path)) as zf:
        manifest = zf.read("TRANSFER-MANIFEST.txt").decode()
    # Once it leaves the repository the git history does not travel with it.
    for field in ("source commit", "source branch", "benchmark", "classification"):
        assert field in manifest


def test_checksums_cover_every_file(tmp_path):
    with zipfile.ZipFile(build(tmp_path)) as zf:
        names = set(zf.namelist())
        summed = {line.split("  ", 1)[1] for line in zf.read("SHA256SUMS").decode().splitlines()}
    unsummed = names - summed - {"SHA256SUMS", "TRANSFER-MANIFEST.txt"}
    assert not unsummed, f"files in the archive with no checksum: {sorted(unsummed)}"


def test_verify_detects_tampering(tmp_path):
    archive = build(tmp_path)
    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(archive) as src, zipfile.ZipFile(tampered, "w") as dst:
        for info in src.infolist():
            body = src.read(info.filename)
            if info.filename == "ansible/controls/rhel8_cat2_controls.yml":
                body = body + b"\n# injected\n"
            dst.writestr(info, body)
    assert pkg.verify(tampered) == 1


def test_secret_scan_blocks_a_private_key(tmp_path):
    root = tmp_path / "src"
    (root / "ansible").mkdir(parents=True)
    # Assembled at run time rather than written literally: a literal key banner
    # in this file would be detected in the repository it ships from, which is
    # the scanner working correctly and the test breaking the build.
    marker = "-----BEGIN " + "RSA PRIVATE KEY" + "-----"
    (root / "ansible" / "leak.yml").write_text(
        f"---\nkey: |\n  {marker}\n  AAAA\n", encoding="utf-8"
    )
    findings = pkg.scan_for_secrets(root, pkg.collect(root))
    assert any("private key" in f for f in findings)


def test_secret_scan_allows_credential_shells_in_the_aap_config():
    # credentials.yml names become_method and ssh_key_data without values; the
    # scanner must not block a legitimate build over them.
    files = pkg.collect(REPO)
    assert not pkg.scan_for_secrets(REPO, files)
