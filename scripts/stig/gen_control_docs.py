#!/usr/bin/env python3
"""Generate the per-control check/remediation reference from the DISA export.

Hand-written compliance documentation drifts. Someone adds a control to the
role and forgets the table; DISA renames a rule ID; a fix text changes wording
between releases. The document keeps asserting a coverage that stopped being
true, and nobody notices until an assessor counts the rows.

So this generates the reference instead. Every control in the export produces
exactly one check and one remediation section, quoted verbatim from the
benchmark, joined to what this repository does about it. The header states the
counts, so "N controls, N checks, N remediations" is computed from the source
rather than asserted by a human.

Run with --check in CI to fail the build when the document is stale.

  python scripts/stig/gen_control_docs.py --write
  python scripts/stig/gen_control_docs.py --check
"""

from __future__ import annotations

import argparse
import difflib
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

# Importable as `scripts.stig.gen_control_docs` and runnable as a script from
# the repository root; the latter needs the root on sys.path.
if __package__ in (None, ""):  # pragma: no cover - script entry only
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.stig import parse_disa_export as disa  # noqa: E402

try:
    import yaml
except ImportError:  # pragma: no cover - environment problem, not logic
    sys.stderr.write("PyYAML is required: pip install -r scripts/stig/requirements.txt\n")
    raise

DEFAULT_EXPORTS = [Path("ansible/controls/disa-exports")]
DEFAULT_MANIFEST = Path("ansible/controls/rhel8_cat2_controls.yml")
DEFAULT_OUTPUT = Path("docs/CONTROL-REFERENCE.md")
TASKS_DIR = Path("ansible/roles/rhel8_stig_cat2/tasks")
DEFAULTS_FILE = Path("ansible/roles/rhel8_stig_cat2/defaults/main.yml")
JOB_TEMPLATES = Path("aap/controller/job_templates.yml")

# Which AAP job template applies a control, derived from its remediation
# category rather than listed per control - the category IS the blast-radius
# classification, so deriving keeps the two from disagreeing.
AAP_TEMPLATE = {
    "automated": "STIG CAT II - Remediate (Automated and Assisted)",
    "assisted": "STIG CAT II - Remediate (Automated and Assisted)",
    "gated": "STIG CAT II - Remediate (Gated Control)",
    "manual": None,
}
AAP_APPROVAL = {
    "automated": "Tier approval node in the staged-rollout workflow.",
    "assisted": "Tier approval node in the staged-rollout workflow.",
    "gated": "**Dedicated approval node, one control per launch.**",
    "manual": "Not applicable - no remediation template exists.",
}
# Owner paths from .github/CODEOWNERS, for the review-gate column.
CODEOWNERS = {
    "ansible/roles/": "@your-org/platform-security @your-org/linux-engineering",
    "ansible/controls/": "@your-org/platform-security @your-org/isso",
    "ansible/inventory/group_vars/": "@your-org/platform-security @your-org/isso",
    "scripts/stig/": "@your-org/platform-security",
}

REMEDIATION_LABEL = {
    "automated": "Automated - the role enforces this with no human decision required.",
    "gated": "Gated - off by default; needs organization-supplied data before it runs.",
    "assisted": "Assisted - the role converges what it safely can and reports the rest.",
    "manual": "Manual - no automatable fix exists; the role gathers evidence for a human.",
}


REPO_ROOT = Path(__file__).resolve().parents[2]


def display_path(path: Path) -> str:
    """Render a path the same way however the generator was invoked.

    The document embeds its source path. Without normalisation the output
    differs between `--export ansible/...` and `--export /abs/ansible/...`,
    which would make the --check gate fail on invocation style rather than on
    real staleness.
    """
    resolved = path.resolve()
    try:
        return resolved.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return resolved.name


class DocsError(Exception):
    """Raised for bad input so main() can exit 2 instead of tracebacking."""


# Orchestration and helper files mention every STIG ID, so a naive content
# search resolves each control to main.yml instead of the file that implements
# it. They are excluded from the fallback scan.
ORCHESTRATION_FILES = frozenset({"main.yml", "record.yml", "preflight.yml", "evidence.yml"})


def find_task_file(stig_id: str, tasks_dir: Path) -> Path | None:
    """Locate the task file implementing a control.

    Most controls have a file named for their STIG ID. The three sysctl network
    controls share one file, because splitting them would write the same
    /etc/sysctl.d file from three places and race on the reload.
    """
    direct = tasks_dir / f"{stig_id}.yml"
    if direct.exists():
        return direct
    for candidate in sorted(tasks_dir.glob("*.yml")):
        if candidate.name in ORCHESTRATION_FILES:
            continue
        if stig_id in candidate.read_text(encoding="utf-8"):
            return candidate
    return None


def load_role_defaults(path: Path) -> dict[str, object]:
    """Read the role's tunables so each control can list the ones that steer it."""
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        # Missing defaults should degrade the document, not break the build.
        return {}


def control_variables(
    stig_id: str, task_file: Path | None, defaults: dict[str, object]
) -> list[tuple[str, object]]:
    """Derive the tunables that steer one control.

    Two sources, because neither alone is right:

      * any default whose name carries this control's six-digit ID. This catches
        `stig_040137_enforce` wherever it is referenced, including the `when:`
        in main.yml rather than the task file itself.
      * any non-numbered default the task file actually references. This catches
        the shared switches (`stig_audit_only`, `stig_backup`,
        `stig_mfa_alternate`) without dragging in the *other* controls' settings
        from a task file that several controls share, like sysctl_network.yml.
    """
    digits = stig_id.rsplit("-", 1)[-1]
    names = {k for k in defaults if digits in k}
    if task_file is not None:
        body = task_file.read_text(encoding="utf-8")
        referenced = set(re.findall(r"\bstig_[a-z0-9_]+", body))
        names |= {k for k in referenced if k in defaults and not re.search(r"_\d{6}_", k)}
    return [(k, defaults[k]) for k in sorted(names)]


def codeowners_for(path: Path) -> str:
    # Normalised first: matching on the raw path makes the output depend on
    # whether the caller passed a relative or absolute tasks directory, which
    # breaks the --check gate on invocation style rather than real staleness.
    posix = display_path(path)
    for prefix, owners in CODEOWNERS.items():
        if posix.startswith(prefix):
            return owners
    return "@your-org/platform-security"


def fmt_value(value: object) -> str:
    if isinstance(value, bool):
        return "`true`" if value else "`false`"
    if value == "" or value == [] or value == {}:
        return "_(unset)_"
    return f"`{value}`"


def load_manifest(path: Path) -> dict[str, dict[str, Any]]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise DocsError(f"{path}: cannot read control manifest ({exc})") from exc
    return {c["stig_id"]: c for c in raw.get("controls", []) if c.get("stig_id")}


def fence(text: str) -> str:
    """Quote benchmark text as a code block, neutralising any fence inside it."""
    return "```text\n" + text.replace("```", "'''") + "\n```"


def render(
    controls: list[dict[str, Any]],
    manifest: dict[str, dict[str, Any]],
    tasks_dir: Path,
    export_paths: Sequence[Path],
    defaults: dict[str, object] | None = None,
) -> str:
    checks = sum(1 for c in controls if c.get("check_text"))
    fixes = sum(1 for c in controls if c.get("fix_text"))
    covered = {c["stig_id"]: find_task_file(c["stig_id"], tasks_dir) for c in controls}
    implemented = sum(1 for path in covered.values() if path is not None)
    sources = [display_path(p) for p in export_paths]
    defaults = defaults if defaults is not None else {}

    lines: list[str] = [
        "<!-- GENERATED FILE - DO NOT EDIT BY HAND.",
        "     Regenerate with: python scripts/stig/gen_control_docs.py --write",
        "     Sources: " + ", ".join(sources) + " -->",
        "",
        "# RHEL 8 CAT II control reference",
        "",
        f"**{len(controls)} controls - {checks} checks - {fixes} remediations.** "
        "One check and one remediation per control, quoted verbatim from the DISA "
        "export, joined to what this repository does about each one.",
        "",
        "Counts are computed at generation time from "
        + ", ".join(f"`{s}`" for s in sources)
        + ". Add another export to that directory and regenerate; the totals follow "
        "the source. The full RHEL 8 V2R8 benchmark contains 314 CAT II rules, so "
        "this set is expected to grow.",
        "",
        f"Implemented by the role: **{implemented} of {len(controls)}**.",
        "",
        "## Index",
        "",
        "| # | STIG ID | Group ID | Severity | Approach | Enforced by |",
        "| ---: | --- | --- | --- | --- | --- |",
    ]

    for number, control in enumerate(controls, start=1):
        stig_id = control["stig_id"]
        entry = manifest.get(stig_id, {})
        task = covered[stig_id]
        enforced = f"`{task.name}`" if task else "**not implemented**"
        anchor = stig_id.lower()
        lines.append(
            f"| {number} | [`{stig_id}`](#{anchor}) | {control.get('group_id', '')} | "
            f"{control.get('severity', '')} | {entry.get('remediation', 'unreviewed')} | {enforced} |"
        )

    missing = [sid for sid, path in covered.items() if path is None]
    if missing:
        lines += [
            "",
            "> **Coverage gap.** These controls appear in the benchmark export but have "
            "no task file in the role, so the baseline does not enforce them:",
            "",
        ] + [f"> - `{sid}`" for sid in missing]

    lines += ["", "---", ""]

    for number, control in enumerate(controls, start=1):
        stig_id = control["stig_id"]
        entry = manifest.get(stig_id, {})
        task = covered[stig_id]

        lines += [
            f"## {stig_id}",
            "",
            f"**{control.get('title', '(no title)')}**",
            "",
            "| | |",
            "| --- | --- |",
            f"| Control | {number} of {len(controls)} |",
            f"| Group ID | {control.get('group_id', '')} |",
            f"| Rule ID | `{control.get('rule_id', '')}` |",
            f"| Severity | {control.get('severity', '')} |",
            f"| SRG | {control.get('srg', '')} |",
            f"| CCI | {', '.join(control.get('cci', [])) or 'n/a'} |",
            f"| NIST 800-53 | {', '.join(control.get('nist', [])) or 'n/a'} |",
            f"| Approach | {REMEDIATION_LABEL.get(entry.get('remediation', ''), 'Not yet reviewed.')} |",
            f"| Residual risk | {entry.get('risk', 'unknown')} |",
            f"| Reboot required | {entry.get('reboot_required', 'unknown')} |",
            "",
            "### Check",
            "",
            fence(control.get("check_text", "(no check text in the export)")),
            "",
            "### Remediation (DISA fix text)",
            "",
            fence(control.get("fix_text", "(no fix text in the export)")),
            "",
            "### How this repository remediates it",
            "",
        ]

        remediation = entry.get("remediation", "")
        if task:
            task_display = display_path(task)
            lines += [
                f"Enforced by [`{task_display}`](../{task_display}), runnable on its "
                f"own with `ansible-playbook remediate.yml --tags {stig_id}`.",
                "",
            ]
        else:
            lines += [
                "**Not implemented.** No task file in the role covers this control. "
                "It is listed here so the gap is visible rather than absent.",
                "",
            ]

        note = " ".join(str(entry.get("notes", "")).split())
        if note:
            lines += [f"> {note}", ""]
        if entry.get("applicability"):
            lines += [f"Applicability: {entry['applicability']}.", ""]

        # ---- GitHub ------------------------------------------------------
        owners = codeowners_for(task) if task else "@your-org/platform-security"
        lines += [
            "#### Mitigation path: GitHub",
            "",
            "| | |",
            "| --- | --- |",
            f"| Source of truth | [`{display_path(task)}`](../{display_path(task)}) |"
            if task
            else "| Source of truth | _no task file_ |",
            f"| Required reviewers | `{owners}` (CODEOWNERS) |",
            "| Merge gate | `stig-validate`: ansible-lint (production profile), "
            "yamllint, playbook syntax, evidence-schema contract, benchmark drift, "
            "AAP boundary tests |",
            f"| Risk classification | `{remediation}` / residual risk "
            f"`{entry.get('risk', 'unknown')}` - reviewed in "
            "[`rhel8_cat2_controls.yml`](../ansible/controls/rhel8_cat2_controls.yml) |",
            "| Change record | the merge commit; branch protection forbids force-push, "
            "so the history is the evidence |",
            "",
        ]

        # ---- AAP ---------------------------------------------------------
        template = AAP_TEMPLATE.get(remediation)
        variables = control_variables(stig_id, task, defaults)
        lines += [
            "#### Mitigation path: Ansible Automation Platform",
            "",
            "| | |",
            "| --- | --- |",
            "| Project | `RHEL 8 STIG CAT II` (syncs this repo, revision updated on launch) |",
            f"| Job tag | `{stig_id}` |",
            f"| Remediation template | {f'`{template}`' if template else '**none** - no automatable fix'} |",
            "| Audit template | `STIG CAT II - Audit` (read-only, scheduled nightly) |",
            f"| Approval | {AAP_APPROVAL.get(remediation, 'Unclassified.')} |",
            f"| Evidence | `{stig_id}` entry in the per-host evidence document, "
            "collected by `STIG CAT II - Evidence Report` |",
            "",
        ]
        if variables:
            lines += (
                [
                    "Tunables that steer this control, with their role defaults:",
                    "",
                    "| Variable | Default |",
                    "| --- | --- |",
                ]
                + [f"| `{name}` | {fmt_value(value)} |" for name, value in variables]
                + [""]
            )

        lines += ["---", ""]

    return "\n".join(lines).rstrip() + "\n"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="gen-control-docs",
        description="Generate the per-control check/remediation reference.",
    )
    parser.add_argument(
        "--exports",
        nargs="+",
        type=Path,
        default=DEFAULT_EXPORTS,
        help="DISA exports, or directories of them (default: %(default)s).",
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--tasks-dir", type=Path, default=TASKS_DIR)
    parser.add_argument("--defaults", type=Path, default=DEFAULTS_FILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true", help="Write the document to --output.")
    mode.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 with a diff if --output is stale. For CI.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        export_files = disa.collect_export_files(args.exports)
        controls = disa.parse_exports(args.exports)
    except (OSError, FileNotFoundError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2

    if not controls:
        sys.stderr.write(f"error: no controls parsed from {args.exports}\n")
        return 2

    try:
        manifest = load_manifest(args.manifest)
    except DocsError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2

    rendered = render(
        controls, manifest, args.tasks_dir, export_files, load_role_defaults(args.defaults)
    )

    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.exists() else ""
        if current == rendered:
            print(f"{args.output} is up to date ({len(controls)} controls).")
            return 0
        sys.stderr.write(f"{args.output} is stale. Regenerate with --write.\n\n")
        sys.stderr.writelines(
            difflib.unified_diff(
                current.splitlines(keepends=True),
                rendered.splitlines(keepends=True),
                fromfile=f"{args.output} (committed)",
                tofile=f"{args.output} (generated)",
            )
        )
        return 1

    if args.write:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
        print(
            f"Wrote {args.output}: {len(controls)} controls, "
            f"{sum(1 for c in controls if c.get('check_text'))} checks, "
            f"{sum(1 for c in controls if c.get('fix_text'))} remediations."
        )
        return 0

    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
