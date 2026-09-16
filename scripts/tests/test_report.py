"""Tests for the STIG evidence reporter.

These cover the decisions that would quietly produce a false compliance record:
a missing result being read as a pass, an unknown status slipping through, a
stale evidence schema, and a waiver silently hiding a real finding.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from scripts.stig import report

MANIFEST = Path(__file__).resolve().parents[2] / "ansible/controls/rhel8_cat2_controls.yml"


def write_evidence(tmp_path: Path, host: str, results: list[dict], **overrides) -> Path:
    doc = {
        "schema": report.EVIDENCE_SCHEMA,
        "host": host,
        "os": "RedHat 8.10",
        "benchmark": "RHEL 8 STIG V2R8 (2026-07-01) CAT II",
        "run_id": "12345",
        "run_started": "2026-09-16T00:00:00Z",
        "audit_only": False,
        "check_mode": False,
        "reboot_required": False,
        "results": results,
    }
    doc.update(overrides)
    path = tmp_path / f"{host}.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


@pytest.fixture
def controls() -> dict[str, report.Control]:
    return report.load_controls(MANIFEST)


# --- manifest ---------------------------------------------------------------


def test_manifest_loads_every_control(controls):
    # Grows as exports are added; the point is that every export control is present.
    from scripts.stig import parse_disa_export as disa

    exported = {c["stig_id"] for c in disa.parse_exports([MANIFEST.parent / "disa-exports"])}
    assert set(controls) == exported
    assert len(controls) >= 29
    assert "RHEL-08-040287" in controls
    assert controls["RHEL-08-040287"].nist  # NIST mapping is what the POA&M cites


def test_manifest_rejects_duplicate_controls(tmp_path):
    path = tmp_path / "dupe.yml"
    path.write_text(
        "controls:\n  - stig_id: RHEL-08-000001\n  - stig_id: RHEL-08-000001\n",
        encoding="utf-8",
    )
    with pytest.raises(report.ReportError, match="duplicate control"):
        report.load_controls(path)


# --- evidence loading -------------------------------------------------------


def test_rejects_unknown_evidence_schema(tmp_path):
    path = tmp_path / "old.json"
    path.write_text(json.dumps({"schema": "stig-evidence/v0", "results": []}), encoding="utf-8")
    with pytest.raises(report.ReportError, match="unsupported evidence schema"):
        report.HostEvidence.from_file(path)


def test_rejects_unknown_status(tmp_path):
    path = write_evidence(tmp_path, "h1", [{"stig_id": "RHEL-08-040221", "status": "Compliant"}])
    with pytest.raises(report.ReportError, match="not one of"):
        report.HostEvidence.from_file(path)


def test_missing_evidence_directory_is_an_error(tmp_path):
    with pytest.raises(report.ReportError, match="no evidence documents found"):
        report.load_evidence([tmp_path])


# --- reconciliation: the part that must never invent a pass ------------------


def test_control_absent_from_evidence_is_not_reviewed_not_passed(tmp_path, controls):
    # Host only reported one of the fifteen controls.
    path = write_evidence(
        tmp_path, "h1", [{"stig_id": "RHEL-08-040221", "status": report.STATUS_PASS}]
    )
    matrix = report.reconcile([report.HostEvidence.from_file(path)], controls)
    assert matrix["h1"]["RHEL-08-040221"].status == report.STATUS_PASS
    assert matrix["h1"]["RHEL-08-040222"].status == report.STATUS_UNKNOWN
    counts = report.tally(matrix)
    assert counts[report.STATUS_PASS] == 1
    assert counts[report.STATUS_UNKNOWN] == len(controls) - 1


def test_not_reviewed_gates_the_pipeline(tmp_path, controls):
    path = write_evidence(tmp_path, "h1", [])
    matrix = report.reconcile([report.HostEvidence.from_file(path)], controls)
    findings = report.gating_findings(matrix, waived=set())
    assert len(findings) == len(controls)


def test_not_applicable_does_not_gate(tmp_path, controls):
    results = [
        {"stig_id": c, "status": report.STATUS_PASS} for c in controls if c != "RHEL-08-020035"
    ]
    results.append({"stig_id": "RHEL-08-020035", "status": report.STATUS_NA, "detail": "RHEL 8.6"})
    path = write_evidence(tmp_path, "h1", results)
    matrix = report.reconcile([report.HostEvidence.from_file(path)], controls)
    assert report.gating_findings(matrix, waived=set()) == []


def test_open_findings_are_reported_before_not_reviewed(tmp_path, controls):
    path = write_evidence(
        tmp_path,
        "h1",
        [
            {"stig_id": "RHEL-08-040400", "status": report.STATUS_OPEN, "detail": "gated"},
            {"stig_id": "RHEL-08-040221", "status": report.STATUS_PASS},
        ],
    )
    matrix = report.reconcile([report.HostEvidence.from_file(path)], controls)
    findings = report.gating_findings(matrix, waived=set())
    assert findings[0].status == report.STATUS_OPEN
    assert findings[0].stig_id == "RHEL-08-040400"


# --- waivers ----------------------------------------------------------------


def test_waiver_suppresses_the_gate_but_keeps_the_poam_row(tmp_path, controls):
    results = [
        {"stig_id": c, "status": report.STATUS_PASS} for c in controls if c != "RHEL-08-040400"
    ]
    results.append({"stig_id": "RHEL-08-040400", "status": report.STATUS_OPEN, "detail": "gated"})
    path = write_evidence(tmp_path, "h1", results)
    matrix = report.reconcile([report.HostEvidence.from_file(path)], controls)
    waived = {"RHEL-08-040400"}

    assert report.gating_findings(matrix, waived) == []

    rows = report.render_poam(controls, matrix, waived, completion_days=30)
    assert len(rows) == 1
    assert rows[0]["STIG ID"] == "RHEL-08-040400"
    assert rows[0]["Status"] == "Risk Accepted"


def test_unknown_waiver_is_a_usage_error(tmp_path, capsys):
    write_evidence(tmp_path, "h1", [])
    rc = report.main(
        [
            str(tmp_path),
            "--controls",
            str(MANIFEST),
            "--waive",
            "RHEL-08-999999",
            "--markdown",
            str(tmp_path / "out.md"),
        ]
    )
    assert rc == 2
    assert "not present in the manifest" in capsys.readouterr().err


# --- rendering --------------------------------------------------------------


def test_poam_only_lists_non_compliant_controls(tmp_path, controls):
    results = [{"stig_id": c, "status": report.STATUS_PASS} for c in controls]
    path = write_evidence(tmp_path, "h1", results)
    matrix = report.reconcile([report.HostEvidence.from_file(path)], controls)
    assert report.render_poam(controls, matrix, set(), 30) == []


def test_junit_marks_open_as_failure_and_na_as_skipped(tmp_path, controls):
    results = [{"stig_id": c, "status": report.STATUS_PASS} for c in controls]
    results[0] = {"stig_id": results[0]["stig_id"], "status": report.STATUS_OPEN, "detail": "x"}
    results[1] = {"stig_id": results[1]["stig_id"], "status": report.STATUS_NA, "detail": "n/a"}
    path = write_evidence(tmp_path, "h1", results)
    matrix = report.reconcile([report.HostEvidence.from_file(path)], controls)

    out = tmp_path / "junit.xml"
    report.render_junit(controls, matrix, set()).write(out)
    suite = ET.parse(out).getroot().find("testsuite")
    assert suite.get("failures") == "1"
    assert suite.get("skipped") == "1"
    assert suite.get("tests") == str(len(controls))


def test_markdown_surfaces_pending_reboots(tmp_path, controls):
    path = write_evidence(
        tmp_path,
        "h1",
        [
            {
                "stig_id": "RHEL-08-030655",
                "status": report.STATUS_OPEN,
                "detail": "auditd immutable",
                "reboot_required": True,
            }
        ],
        reboot_required=True,
    )
    evidence = [report.HostEvidence.from_file(path)]
    markdown = report.render_markdown(
        evidence, controls, report.reconcile(evidence, controls), set()
    )
    assert "Pending reboots" in markdown
    assert "auditd immutable" in markdown


# --- CLI contract -----------------------------------------------------------


def test_cli_exits_1_on_open_findings_and_writes_all_artifacts(tmp_path, controls):
    results = [{"stig_id": c, "status": report.STATUS_PASS} for c in controls]
    results[0] = {"stig_id": results[0]["stig_id"], "status": report.STATUS_OPEN, "detail": "x"}
    write_evidence(tmp_path, "h1", results)

    md, poam, junit = tmp_path / "s.md", tmp_path / "p.csv", tmp_path / "j.xml"
    rc = report.main(
        [
            str(tmp_path),
            "--controls",
            str(MANIFEST),
            "--markdown",
            str(md),
            "--poam",
            str(poam),
            "--junit",
            str(junit),
        ]
    )
    assert rc == 1
    assert md.exists() and poam.exists() and junit.exists()
    assert "RHEL 8 STIG CAT II compliance" in md.read_text()


def test_cli_exit_zero_flag_overrides_the_gate(tmp_path, controls):
    write_evidence(tmp_path, "h1", [])
    rc = report.main(
        [
            str(tmp_path),
            "--controls",
            str(MANIFEST),
            "--markdown",
            str(tmp_path / "s.md"),
            "--exit-zero",
        ]
    )
    assert rc == 0


def test_cli_exits_0_when_fully_compliant(tmp_path, controls):
    results = [{"stig_id": c, "status": report.STATUS_PASS} for c in controls]
    write_evidence(tmp_path, "h1", results)
    rc = report.main(
        [str(tmp_path), "--controls", str(MANIFEST), "--markdown", str(tmp_path / "s.md")]
    )
    assert rc == 0
