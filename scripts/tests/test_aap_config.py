"""Tests for the AAP controller configuration.

These enforce one invariant that a human cannot reliably hold: the boundary
between what the automated template may apply and what requires an approval
node must match the manifest's own risk classification.

The first version of job_templates.yml got this wrong - RHEL-08-040321 is gated
(it needs ISSO sign-off and a reboot) but appeared in the automated template's
tag list and not in the gated survey. That is a control with a documented
approval requirement running through a template with no approval node, which is
precisely the failure these tests exist to catch.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
MANIFEST = REPO / "ansible/controls/rhel8_cat2_controls.yml"
CONTROLLER = REPO / "aap/controller"

AUTOMATED_TEMPLATE = "STIG CAT II - Remediate (Automated and Assisted)"
GATED_TEMPLATE = "STIG CAT II - Remediate (Gated Control)"


def load(name: str) -> dict:
    return yaml.safe_load((CONTROLLER / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def controls() -> list[dict]:
    return yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))["controls"]


@pytest.fixture(scope="module")
def templates() -> dict[str, dict]:
    return {t["name"]: t for t in load("job_templates.yml")["controller_templates"]}


def ids_by_remediation(controls: list[dict], *kinds: str) -> set[str]:
    return {c["stig_id"] for c in controls if c["remediation"] in kinds}


def template_tags(template: dict) -> set[str]:
    return {t.strip() for t in template["job_tags"].replace("\n", " ").split(",") if t.strip()}


def survey_choices(template: dict, variable: str) -> set[str]:
    spec = next(q for q in template["survey_spec"]["spec"] if q["variable"] == variable)
    return {c.split("#")[0].strip() for c in spec["choices"]}


# --- the boundary that matters ---------------------------------------------


def test_automated_template_covers_exactly_automated_and_assisted(controls, templates):
    assert template_tags(templates[AUTOMATED_TEMPLATE]) == ids_by_remediation(
        controls, "automated", "assisted"
    )


def test_no_gated_control_can_run_through_the_unapproved_template(controls, templates):
    gated = ids_by_remediation(controls, "gated")
    leaked = template_tags(templates[AUTOMATED_TEMPLATE]) & gated
    assert not leaked, (
        f"gated control(s) {sorted(leaked)} are tagged into {AUTOMATED_TEMPLATE}, "
        "which has no approval node"
    )


def test_gated_survey_offers_every_gated_control(controls, templates):
    assert survey_choices(templates[GATED_TEMPLATE], "stig_gated_control") == ids_by_remediation(
        controls, "gated"
    )


def test_manual_controls_are_not_in_any_remediation_template(controls, templates):
    manual = ids_by_remediation(controls, "manual")
    assert manual, "expected at least one manual control in the manifest"
    assert not (template_tags(templates[AUTOMATED_TEMPLATE]) & manual)
    assert not (survey_choices(templates[GATED_TEMPLATE], "stig_gated_control") & manual)


# --- safety properties of the templates themselves --------------------------


def test_check_mode_template_cannot_be_flipped_to_apply(templates):
    check = templates["STIG CAT II - Remediate (Check Mode)"]
    assert check["job_type"] == "check"
    # If the job type could be asked at launch, the dry run is an apply waiting
    # for a wrong dropdown.
    assert not check.get("ask_job_type_on_launch", False)


def test_audit_template_never_writes(templates):
    audit = templates["STIG CAT II - Audit"]
    assert audit["playbook"] == "ansible/audit.yml"
    assert not audit.get("ask_job_type_on_launch", False)


def test_every_writing_template_demands_a_change_record(templates):
    for name in (AUTOMATED_TEMPLATE, GATED_TEMPLATE):
        spec = templates[name]["survey_spec"]["spec"]
        ticket = next(q for q in spec if q["variable"] == "stig_change_ticket")
        assert ticket["required"] is True


def test_project_refuses_stale_content(controls):
    project = load("projects.yml")["controller_projects"][0]
    # Without this, a job can run a commit that is no longer on the branch, and
    # "which commit hardened this host" stops having an answer.
    assert project["scm_update_on_launch"] is True
    assert project["scm_update_cache_timeout"] == 0


def test_no_secret_material_is_committed():
    forbidden = ("ssh_key_data", "become_password", "-----BEGIN", "oauth_token")
    for path in sorted(CONTROLLER.glob("*.yml")):
        body = path.read_text(encoding="utf-8")
        for needle in forbidden:
            # Allowed in comments explaining where the value comes from.
            hits = [
                line
                for line in body.splitlines()
                if needle in line and not line.strip().startswith("#")
            ]
            assert not hits, f"{path.name} appears to contain secret material: {hits}"


# --- schedules and separation of duties -------------------------------------


def test_only_read_only_templates_are_scheduled():
    scheduled = {s["unified_job_template"] for s in load("schedules.yml")["controller_schedules"]}
    writing = {AUTOMATED_TEMPLATE, GATED_TEMPLATE}
    assert not (scheduled & writing), (
        "a template that modifies hosts is on a timer; remediation must be "
        "launched by a person against a change record"
    )


def test_approvers_hold_no_execute_role():
    roles = load("rbac.yml")["controller_roles"]
    approver_roles = {r["role"] for r in roles if r.get("team") == "STIG Approvers"}
    assert approver_roles == {"approval"}, (
        "an approver who can also launch can approve their own change"
    )


def test_operators_cannot_launch_anything_that_writes():
    roles = load("rbac.yml")["controller_roles"]
    operator_templates = {r.get("job_template") for r in roles if r.get("team") == "STIG Operators"}
    assert AUTOMATED_TEMPLATE not in operator_templates
    assert GATED_TEMPLATE not in operator_templates


def test_workflow_gates_production_behind_a_second_approval():
    workflow = load("workflow_job_templates.yml")["controller_workflows"][0]
    nodes = {n["identifier"]: n for n in workflow["simplified_workflow_nodes"]}
    approvals = [n for n in nodes.values() if "approval_node" in n]
    assert len(approvals) == 2, "staging and production need separate approvals"
    # Production must be reachable only from a clean staging re-audit.
    assert nodes["verify-staging"]["success_nodes"] == ["approve-production"]
    assert "failure_nodes" not in nodes["verify-staging"], (
        "a failed staging audit must not have a path onward to production"
    )
