"""Tests for the security-category layer.

Categories exist so drift is monitored per security area rather than as one
fleet-wide pass/fail. That only works if three things stay in step with the
manifest: the Ansible tags, the reporter's scoping, and the generated AAP
drift audits. Each is checked here, because each fails silently when it drifts
- a category with no tag, no audit or no scoping reports clean forever because
nothing ever looks at it.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

from scripts.stig import gen_aap_categories as gen_cat
from scripts.stig import report

REPO = Path(__file__).resolve().parents[2]
MANIFEST = REPO / "ansible/controls/rhel8_cat2_controls.yml"
MAIN_YML = REPO / "ansible/roles/rhel8_stig_cat2/tasks/main.yml"
CATEGORY_AUDITS = REPO / "aap/controller/category_audits.yml"


@pytest.fixture(scope="module")
def controls() -> list[dict]:
    return yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))["controls"]


@pytest.fixture(scope="module")
def loaded() -> dict[str, report.Control]:
    return report.load_controls(MANIFEST)


# --- the manifest ------------------------------------------------------------


def test_every_control_has_a_category(controls):
    uncategorized = [c["stig_id"] for c in controls if not c.get("category")]
    assert not uncategorized


def test_family_is_derived_from_the_nist_mapping(loaded):
    # Derived, not stored, so the two cannot disagree.
    assert loaded["RHEL-08-010455"].family == "AC"
    assert loaded["RHEL-08-030655"].family == "AU"
    assert loaded["RHEL-08-040287"].family == "SC"
    assert loaded["RHEL-08-010385"].family == "IA"
    assert loaded["RHEL-08-010019"].family == "CM"


# --- the Ansible tags --------------------------------------------------------


def test_every_control_is_reachable_by_its_category_tag(controls):
    body = MAIN_YML.read_text(encoding="utf-8")
    tag_lines = [line for line in body.splitlines() if "tags: [" in line]
    by_stig: dict[str, set[str]] = {}
    for line in tag_lines:
        tags = {t.strip() for t in line.split("[", 1)[1].rstrip("]").split(",")}
        for tag in tags:
            if re.fullmatch(r"RHEL-08-\d{6}", tag):
                by_stig[tag] = tags

    for control in controls:
        tags = by_stig.get(control["stig_id"])
        assert tags, f"{control['stig_id']} has no include task in main.yml"
        assert f"cat_{control['category']}" in tags, (
            f"{control['stig_id']} is category {control['category']} but its include "
            f"does not carry cat_{control['category']}; a category-scoped audit "
            "would skip it and the category would report clean"
        )


def test_controls_sharing_a_task_file_share_a_category(controls):
    # sysctl_network.yml covers three controls under one include, so one tag has
    # to be right for all three.
    shared = {"RHEL-08-040221", "RHEL-08-040222", "RHEL-08-040287"}
    cats = {c["category"] for c in controls if c["stig_id"] in shared}
    assert len(cats) == 1, f"controls sharing one include disagree on category: {cats}"


# --- the reporter ------------------------------------------------------------


def _evidence(tmp_path: Path, host: str, statuses: dict[str, str], ids: list[str]) -> Path:
    results = [
        {"stig_id": i, "status": statuses.get(i, report.STATUS_PASS), "detail": ""} for i in ids
    ]
    doc = {
        "schema": report.EVIDENCE_SCHEMA,
        "host": host,
        "benchmark": "test",
        "results": results,
    }
    path = tmp_path / f"{host}.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def test_rollup_reports_each_category_separately(tmp_path, loaded):
    ids = list(loaded)
    _evidence(tmp_path, "h1", {"RHEL-08-010455": report.STATUS_OPEN}, ids)
    evidence = report.load_evidence([tmp_path])
    matrix = report.reconcile(evidence, loaded)
    rollups = {r.category: r for r in report.rollup_by_category(matrix, loaded, set())}

    assert not rollups["privilege-escalation"].compliant
    assert rollups["privilege-escalation"].open_controls == ("RHEL-08-010455",)
    assert rollups["session-management"].compliant
    assert rollups["authentication"].compliant


def test_not_applicable_counts_toward_a_category_score(tmp_path, loaded):
    ids = list(loaded)
    _evidence(tmp_path, "h1", {"RHEL-08-020035": report.STATUS_NA}, ids)
    evidence = report.load_evidence([tmp_path])
    matrix = report.reconcile(evidence, loaded)
    rollups = {r.category: r for r in report.rollup_by_category(matrix, loaded, set())}
    # A control that does not apply is not a gap in posture.
    assert rollups["session-management"].compliant
    assert rollups["session-management"].score == "100%"


def test_waived_control_does_not_make_its_category_red(tmp_path, loaded):
    ids = list(loaded)
    _evidence(tmp_path, "h1", {"RHEL-08-010455": report.STATUS_OPEN}, ids)
    evidence = report.load_evidence([tmp_path])
    matrix = report.reconcile(evidence, loaded)
    rollups = {r.category: r for r in report.rollup_by_category(matrix, loaded, {"RHEL-08-010455"})}
    # Not red - nobody has to act. But the score stays honest: a risk
    # acceptance does not make the weakness disappear.
    assert rollups["privilege-escalation"].compliant
    assert rollups["privilege-escalation"].score != "100%"


def test_category_scoping_ignores_findings_outside_the_category(tmp_path, capsys):
    controls = report.load_controls(MANIFEST)
    ids = list(controls)
    _evidence(tmp_path, "h1", {"RHEL-08-010455": report.STATUS_OPEN}, ids)

    # An open privilege-escalation finding must not fail a session-management run.
    rc = report.main(
        [
            str(tmp_path),
            "--controls",
            str(MANIFEST),
            "--category",
            "session-management",
            "--markdown",
            str(tmp_path / "a.md"),
        ]
    )
    assert rc == 0
    # ...and must fail its own category's run.
    rc = report.main(
        [
            str(tmp_path),
            "--controls",
            str(MANIFEST),
            "--category",
            "privilege-escalation",
            "--markdown",
            str(tmp_path / "b.md"),
        ]
    )
    assert rc == 1


def test_scoped_totals_exclude_out_of_scope_controls(tmp_path):
    controls = report.load_controls(MANIFEST)
    ids = list(controls)
    _evidence(tmp_path, "h1", {}, ids)
    evidence = report.load_evidence([tmp_path])
    scoped = {k: v for k, v in controls.items() if v.category == "session-management"}
    matrix = report.restrict(report.reconcile(evidence, scoped), scoped)
    assert sum(report.tally(matrix).values()) == len(scoped)


def test_unknown_category_is_a_usage_error(tmp_path, capsys):
    controls = report.load_controls(MANIFEST)
    _evidence(tmp_path, "h1", {}, list(controls))
    rc = report.main(
        [
            str(tmp_path),
            "--controls",
            str(MANIFEST),
            "--category",
            "not-a-category",
            "--markdown",
            str(tmp_path / "a.md"),
        ]
    )
    assert rc == 2
    assert "unknown categor" in capsys.readouterr().err


# --- the generated AAP drift audits ------------------------------------------


def test_generated_category_audits_are_current():
    assert CATEGORY_AUDITS.exists(), "run: python scripts/stig/gen_aap_categories.py --write"
    assert CATEGORY_AUDITS.read_text(encoding="utf-8") == gen_cat.render(
        gen_cat.categories(MANIFEST)
    )


def test_every_category_gets_its_own_audit_and_schedule(controls):
    data = yaml.safe_load(CATEGORY_AUDITS.read_text(encoding="utf-8"))
    categories = {c["category"] for c in controls}
    tags = {t["job_tags"] for t in data["stig_category_templates"]}
    assert tags == {f"cat_{c}" for c in categories}
    assert len(data["stig_category_schedules"]) == len(categories)


def test_every_category_audit_is_read_only():
    data = yaml.safe_load(CATEGORY_AUDITS.read_text(encoding="utf-8"))
    for template in data["stig_category_templates"]:
        assert template["playbook"] == "ansible/audit.yml", template["name"]
        assert template["job_type"] == "run"
        assert not template.get("ask_job_type_on_launch", False)


def test_generated_keys_are_namespaced_so_the_merge_does_not_overwrite():
    data = yaml.safe_load(CATEGORY_AUDITS.read_text(encoding="utf-8"))
    # include_vars over a directory overwrites rather than merges; if these were
    # named controller_templates the hand-written set would vanish silently.
    assert "controller_templates" not in data
    assert "controller_schedules" not in data
    assert set(data) == {
        "stig_category_templates",
        "stig_category_schedules",
        "stig_category_notifications",
    }
    configure = (REPO / "aap/configure.yml").read_text(encoding="utf-8")
    for key in data:
        assert key in configure, f"{key} is generated but never merged in configure.yml"


def test_schedules_are_staggered():
    data = yaml.safe_load(CATEGORY_AUDITS.read_text(encoding="utf-8"))
    times = [re.search(r"T(\d{6})\s", s["rrule"]).group(1) for s in data["stig_category_schedules"]]
    # Nine alerts arriving in the same minute get triaged as one alert.
    assert len(set(times)) == len(times)
