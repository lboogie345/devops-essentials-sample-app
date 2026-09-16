"""Tests for the control reference generator.

The generator exists so the documented control count cannot drift from the
benchmark. These pin that promise: the counts follow the export, a control with
no task file is reported as a gap rather than omitted, and --check catches a
stale committed document.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.stig import gen_control_docs as gen

REPO = Path(__file__).resolve().parents[2]
EXPORTS = [REPO / "ansible/controls/disa-exports"]
MANIFEST = REPO / "ansible/controls/rhel8_cat2_controls.yml"
TASKS = REPO / "ansible/roles/rhel8_stig_cat2/tasks"
COMMITTED = REPO / "docs/CONTROL-REFERENCE.md"


def _controls():
    return gen.disa.parse_exports(EXPORTS)


DEFAULTS = REPO / "ansible/roles/rhel8_stig_cat2/defaults/main.yml"


def _render():
    return gen.render(
        _controls(),
        gen.load_manifest(MANIFEST),
        TASKS,
        gen.disa.collect_export_files(EXPORTS),
        gen.load_role_defaults(DEFAULTS),
    )


@pytest.fixture
def rendered() -> str:
    return _render()


def test_counts_follow_the_export(rendered):
    n = len(_controls())
    # Every control contributes exactly one check and one remediation, so the
    # three totals are equal by construction whatever the export contains.
    assert f"**{n} controls - {n} checks - {n} remediations.**" in rendered
    assert rendered.count("### Check\n") == n
    assert rendered.count("### Remediation (DISA fix text)\n") == n


def test_committed_document_is_current():
    # Guards the same thing CI guards, so a local run catches it first.
    assert COMMITTED.exists(), "run: python scripts/stig/gen_control_docs.py --write"
    assert COMMITTED.read_text(encoding="utf-8") == _render()


def test_every_control_maps_to_its_implementation_not_the_orchestrator(rendered):
    # main.yml names every STIG ID; resolving to it would hide a real gap.
    assert "`main.yml`" not in rendered
    assert "`sysctl_network.yml`" in rendered
    assert "not implemented" not in rendered


def test_sysctl_controls_share_one_task_file():
    for stig_id in ("RHEL-08-040221", "RHEL-08-040222", "RHEL-08-040287"):
        assert gen.find_task_file(stig_id, TASKS).name == "sysctl_network.yml"


def test_unimplemented_control_is_reported_as_a_gap(tmp_path):
    empty_tasks = tmp_path / "tasks"
    empty_tasks.mkdir()
    out = gen.render(
        _controls(),
        gen.load_manifest(MANIFEST),
        empty_tasks,
        gen.disa.collect_export_files(EXPORTS),
        gen.load_role_defaults(DEFAULTS),
    )
    assert "Coverage gap" in out
    assert f"Implemented by the role: **0 of {len(_controls())}**" in out
    assert "**not implemented**" in out


def test_check_and_fix_text_are_quoted_verbatim(rendered):
    assert "$ sudo sysctl net.ipv4.conf.default.rp_filter" in rendered
    assert "declare -xr TMOUT=600" in rendered
    assert "#includedir /etc/sudoers.d" in rendered


def test_check_mode_passes_on_the_committed_document(capsys):
    rc = gen.main(
        [
            "--check",
            "--exports",
            *[str(e) for e in EXPORTS],
            "--manifest",
            str(MANIFEST),
            "--tasks-dir",
            str(TASKS),
            "--output",
            str(COMMITTED),
        ]
    )
    assert rc == 0
    assert "up to date" in capsys.readouterr().out


def test_check_mode_fails_and_diffs_a_stale_document(tmp_path, capsys):
    stale = tmp_path / "CONTROL-REFERENCE.md"
    stale.write_text("# stale\n", encoding="utf-8")
    rc = gen.main(
        [
            "--check",
            "--exports",
            *[str(e) for e in EXPORTS],
            "--manifest",
            str(MANIFEST),
            "--tasks-dir",
            str(TASKS),
            "--output",
            str(stale),
        ]
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "is stale" in err
    assert "RHEL-08-010019" in err  # the diff shows what is missing


def test_missing_export_is_a_usage_error(tmp_path, capsys):
    rc = gen.main(["--write", "--exports", str(tmp_path / "nope.txt")])
    assert rc == 2
    assert "error:" in capsys.readouterr().err


def test_fence_neutralises_a_code_fence_in_benchmark_text():
    assert "```" not in gen.fence("evil ``` text").split("\n")[1]


# --- per-control GitHub and AAP mitigation ----------------------------------


def test_every_control_documents_both_mitigation_paths(rendered):
    n = len(_controls())
    assert rendered.count("#### Mitigation path: GitHub") == n
    assert rendered.count("#### Mitigation path: Ansible Automation Platform") == n


def test_gated_controls_are_marked_as_needing_a_dedicated_approval(rendered):
    import yaml

    manifest = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))["controls"]
    for control in manifest:
        section = rendered.split(f"\n## {control['stig_id']}\n")[1].split("\n## ")[0]
        if control["remediation"] == "gated":
            assert "Dedicated approval node" in section, control["stig_id"]
            assert "Remediate (Gated Control)" in section, control["stig_id"]
        elif control["remediation"] == "manual":
            # A manual control must not advertise a remediation template.
            assert "no automatable fix" in section, control["stig_id"]
        else:
            assert "Remediate (Automated and Assisted)" in section, control["stig_id"]


def test_tunables_do_not_leak_between_controls_sharing_a_task_file():
    defaults = gen.load_role_defaults(DEFAULTS)
    # These three share sysctl_network.yml. Each must list only its own switch.
    names = {
        sid: {v for v, _ in gen.control_variables(sid, gen.find_task_file(sid, TASKS), defaults)}
        for sid in ("RHEL-08-040221", "RHEL-08-040222", "RHEL-08-040287")
    }
    assert "stig_040221_enabled" in names["RHEL-08-040221"]
    assert "stig_040222_enabled" not in names["RHEL-08-040221"]
    assert "stig_040287_enabled" not in names["RHEL-08-040221"]
    assert "stig_040287_apply_to_existing_interfaces" in names["RHEL-08-040287"]


def test_tunables_include_enable_flags_referenced_only_in_main_yml():
    defaults = gen.load_role_defaults(DEFAULTS)
    # stig_010731_enabled gates the include in main.yml, not the task file.
    names = {
        v
        for v, _ in gen.control_variables(
            "RHEL-08-010731", gen.find_task_file("RHEL-08-010731", TASKS), defaults
        )
    }
    assert "stig_010731_enabled" in names


def test_shared_switches_are_attributed_to_the_controls_that_use_them():
    defaults = gen.load_role_defaults(DEFAULTS)
    names = {
        v
        for v, _ in gen.control_variables(
            "RHEL-08-020250", gen.find_task_file("RHEL-08-020250", TASKS), defaults
        )
    }
    assert "stig_mfa_alternate" in names
    assert "stig_audit_only" in names


def test_aap_template_names_in_docs_match_the_controller_config(rendered):
    import yaml

    templates = {
        t["name"]
        for t in yaml.safe_load(
            (REPO / "aap/controller/job_templates.yml").read_text(encoding="utf-8")
        )["controller_templates"]
    }
    for name in set(gen.AAP_TEMPLATE.values()) | {"STIG CAT II - Audit"}:
        if name:
            assert name in templates, f"doc references a template that does not exist: {name}"
            assert name in rendered
