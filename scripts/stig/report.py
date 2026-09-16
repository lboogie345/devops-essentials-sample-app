#!/usr/bin/env python3
"""Turn per-host STIG evidence documents into reviewable compliance output.

The Ansible role writes one JSON evidence document per host. This reads them
alongside the control manifest and emits:

  * a Markdown summary for the GitHub Actions job summary
  * a POA&M-style CSV for the assessment package
  * a JUnit XML result so the pipeline can gate on open findings

Why a separate reporter instead of reading Ansible's own output: the role's
evidence is a statement about control state, while Ansible's output is a
statement about task execution. A task can be `ok` because it was skipped and
`changed` because a file's comment header moved. Neither means compliant. The
evidence document carries the CKL status the role actually determined, which is
what an assessor is entitled to see.

Exit status: 0 when no control is Open, 1 when open findings remain, 2 on a
usage or input error. That makes it usable directly as a pipeline gate.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import sys
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - environment problem, not logic
    sys.stderr.write("PyYAML is required: pip install -r scripts/stig/requirements.txt\n")
    raise

# CKL vocabulary. Anything else in an evidence file is a bug in the role.
STATUS_OPEN = "Open"
STATUS_PASS = "NotAFinding"
STATUS_NA = "Not_Applicable"
STATUS_UNKNOWN = "Not_Reviewed"
VALID_STATUSES = frozenset({STATUS_OPEN, STATUS_PASS, STATUS_NA, STATUS_UNKNOWN})

# Not_Reviewed is not a pass. A host that never evaluated a control is a gap in
# the assessment, so it gates the pipeline alongside Open unless waived.
GATING_STATUSES = frozenset({STATUS_OPEN, STATUS_UNKNOWN})

EVIDENCE_SCHEMA = "stig-evidence/v1"


class ReportError(Exception):
    """Raised for malformed input, so main() can exit 2 rather than traceback."""


@dataclass(frozen=True)
class Control:
    """One STIG control as declared in the manifest."""

    stig_id: str
    group_id: str = ""
    rule_id: str = ""
    severity: str = "CAT II"
    title: str = ""
    cci: tuple[str, ...] = ()
    nist: tuple[str, ...] = ()
    remediation: str = "automated"
    risk: str = "unknown"

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> Control:
        try:
            stig_id = raw["stig_id"]
        except KeyError as exc:
            raise ReportError(f"control entry is missing stig_id: {raw!r}") from exc
        return cls(
            stig_id=stig_id,
            group_id=raw.get("group_id", ""),
            rule_id=raw.get("rule_id", ""),
            severity=raw.get("severity", "CAT II"),
            title=" ".join(str(raw.get("title", "")).split()),
            cci=tuple(raw.get("cci", ())),
            nist=tuple(raw.get("nist", ())),
            remediation=raw.get("remediation", "automated"),
            risk=raw.get("risk", "unknown"),
        )


@dataclass(frozen=True)
class Result:
    """One control's outcome on one host."""

    host: str
    stig_id: str
    status: str
    changed: bool = False
    detail: str = ""
    reboot_required: bool = False


@dataclass
class HostEvidence:
    """A single host's evidence document."""

    host: str
    os: str = ""
    benchmark: str = ""
    run_id: str = ""
    change_ticket: str = ""
    run_started: str = ""
    audit_only: bool = False
    check_mode: bool = False
    reboot_required: bool = False
    results: list[Result] = field(default_factory=list)

    @classmethod
    def from_file(cls, path: Path) -> HostEvidence:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ReportError(f"{path}: not valid JSON ({exc})") from exc
        if not isinstance(raw, dict):
            raise ReportError(f"{path}: expected a JSON object at the top level")

        schema = raw.get("schema")
        if schema != EVIDENCE_SCHEMA:
            raise ReportError(
                f"{path}: unsupported evidence schema {schema!r}; "
                f"this reporter understands {EVIDENCE_SCHEMA!r}. "
                "Re-run the role and the reporter from the same commit."
            )

        host = raw.get("host") or path.stem
        results: list[Result] = []
        for entry in raw.get("results", []):
            status = entry.get("status", STATUS_UNKNOWN)
            if status not in VALID_STATUSES:
                raise ReportError(
                    f"{path}: control {entry.get('stig_id')!r} has status {status!r}, "
                    f"which is not one of {sorted(VALID_STATUSES)}"
                )
            results.append(
                Result(
                    host=host,
                    stig_id=entry.get("stig_id", "UNKNOWN"),
                    status=status,
                    changed=bool(entry.get("changed", False)),
                    detail=" ".join(str(entry.get("detail", "")).split()),
                    reboot_required=bool(entry.get("reboot_required", False)),
                )
            )
        return cls(
            host=host,
            os=raw.get("os", ""),
            benchmark=raw.get("benchmark", ""),
            run_id=str(raw.get("run_id", "")),
            change_ticket=str(raw.get("change_ticket", "")),
            run_started=raw.get("run_started", ""),
            audit_only=bool(raw.get("audit_only", False)),
            check_mode=bool(raw.get("check_mode", False)),
            reboot_required=bool(raw.get("reboot_required", False)),
            results=results,
        )


def load_controls(manifest_path: Path) -> dict[str, Control]:
    """Read the control manifest into an ordered stig_id -> Control mapping."""
    try:
        raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ReportError(f"{manifest_path}: cannot read control manifest ({exc})") from exc
    if not isinstance(raw, dict) or "controls" not in raw:
        raise ReportError(f"{manifest_path}: expected a mapping with a 'controls' key")

    controls: dict[str, Control] = {}
    for entry in raw["controls"]:
        control = Control.from_mapping(entry)
        if control.stig_id in controls:
            raise ReportError(f"{manifest_path}: duplicate control {control.stig_id}")
        controls[control.stig_id] = control
    if not controls:
        raise ReportError(f"{manifest_path}: manifest declares no controls")
    return controls


def load_evidence(paths: Sequence[Path]) -> list[HostEvidence]:
    """Read every evidence document under the given files or directories."""
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(sorted(path.rglob("*.json")))
        elif path.is_file():
            files.append(path)
        else:
            raise ReportError(f"{path}: no such file or directory")
    if not files:
        raise ReportError(
            f"no evidence documents found under {', '.join(str(p) for p in paths)}. "
            "The role writes them only when stig_write_evidence is true."
        )
    return [HostEvidence.from_file(f) for f in files]


def reconcile(
    evidence: Iterable[HostEvidence], controls: dict[str, Control]
) -> dict[str, dict[str, Result]]:
    """Build host -> stig_id -> Result, filling manifest gaps with Not_Reviewed.

    A control the manifest declares but the host never evaluated is the case
    worth catching: a disabled flag or a `when` that silently skipped. Absence
    of a result is recorded as Not_Reviewed, never inferred as a pass.
    """
    matrix: dict[str, dict[str, Result]] = {}
    for host_evidence in evidence:
        by_id = {r.stig_id: r for r in host_evidence.results}
        for stig_id in controls:
            if stig_id not in by_id:
                by_id[stig_id] = Result(
                    host=host_evidence.host,
                    stig_id=stig_id,
                    status=STATUS_UNKNOWN,
                    detail="No result recorded; the control was not evaluated on this host.",
                )
        # Results for controls absent from the manifest still surface, so a
        # role/manifest drift shows up instead of vanishing.
        matrix[host_evidence.host] = by_id
    return matrix


def tally(matrix: dict[str, dict[str, Result]]) -> dict[str, int]:
    counts = dict.fromkeys(sorted(VALID_STATUSES), 0)
    for results in matrix.values():
        for result in results.values():
            counts[result.status] = counts.get(result.status, 0) + 1
    return counts


def gating_findings(matrix: dict[str, dict[str, Result]], waived: set[str]) -> list[Result]:
    """Every result that should stop the pipeline, waivers excluded."""
    findings = [
        result
        for results in matrix.values()
        for result in results.values()
        if result.status in GATING_STATUSES and result.stig_id not in waived
    ]
    findings.sort(key=lambda r: (r.status != STATUS_OPEN, r.stig_id, r.host))
    return findings


# ---------------------------------------------------------------------------
# Output renderers
# ---------------------------------------------------------------------------

_BADGE = {
    STATUS_PASS: "✅",
    STATUS_OPEN: "❌",
    STATUS_NA: "➖",
    STATUS_UNKNOWN: "⚠️",
}


def render_markdown(
    evidence: list[HostEvidence],
    controls: dict[str, Control],
    matrix: dict[str, dict[str, Result]],
    waived: set[str],
) -> str:
    counts = tally(matrix)
    findings = gating_findings(matrix, waived)
    hosts = sorted(matrix)
    benchmark = next((e.benchmark for e in evidence if e.benchmark), "unknown benchmark")
    mode = (
        "audit (no changes made)"
        if all(e.audit_only or e.check_mode for e in evidence)
        else "remediation"
    )

    lines: list[str] = [
        "# RHEL 8 STIG CAT II compliance",
        "",
        f"**Benchmark:** {benchmark}  ",
        f"**Mode:** {mode}  ",
        f"**Hosts:** {len(hosts)}  ",
        *(
            [f"**Change record:** {tickets}  "]
            if (
                tickets := ", ".join(sorted({e.change_ticket for e in evidence if e.change_ticket}))
            )
            else []
        ),
        f"**Generated:** {dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')}",
        "",
        "| Status | Count |",
        "| --- | ---: |",
    ]
    for status in (STATUS_PASS, STATUS_OPEN, STATUS_NA, STATUS_UNKNOWN):
        lines.append(f"| {_BADGE[status]} {status} | {counts.get(status, 0)} |")

    lines += ["", "## Control matrix", ""]
    lines.append("| Control | Title | " + " | ".join(hosts) + " |")
    lines.append("| --- | --- | " + " | ".join("---" for _ in hosts) + " |")
    for stig_id, control in controls.items():
        title = control.title if len(control.title) <= 70 else control.title[:67] + "..."
        cells = []
        for host in hosts:
            result = matrix[host].get(stig_id)
            badge = _BADGE.get(result.status, "?") if result else "?"
            if result and result.changed:
                badge += " 🔧"
            cells.append(badge)
        waiver = " *(waived)*" if stig_id in waived else ""
        lines.append(f"| `{stig_id}`{waiver} | {title} | " + " | ".join(cells) + " |")
    lines += ["", "🔧 = this run changed the host to reach that state.", ""]

    if findings:
        lines += ["## Findings requiring action", ""]
        for result in findings:
            control = controls.get(result.stig_id)
            title = control.title if control else "(not in manifest)"
            nist = ", ".join(control.nist) if control and control.nist else "n/a"
            lines += [
                f"### {_BADGE[result.status]} `{result.stig_id}` on `{result.host}`",
                "",
                f"- **Title:** {title}",
                f"- **Status:** {result.status}",
                f"- **NIST 800-53:** {nist}",
                f"- **Detail:** {result.detail or '(none recorded)'}",
                "",
            ]
    else:
        lines += [
            "## Findings requiring action",
            "",
            "None. Every declared control is NotAFinding or Not_Applicable.",
            "",
        ]

    reboots = sorted({e.host for e in evidence if e.reboot_required})
    if reboots:
        lines += (
            [
                "## Pending reboots",
                "",
                "These hosts have converged configuration that only takes effect after a "
                "reboot, and remain non-compliant on the running system until then:",
                "",
            ]
            + [f"- `{h}`" for h in reboots]
            + [""]
        )
    return "\n".join(lines)


POAM_COLUMNS = [
    "Control Vulnerability Description",
    "STIG ID",
    "Group ID",
    "Rule ID",
    "Severity",
    "Security Control Number",
    "Security Checks (CCI)",
    "Affected Asset",
    "Status",
    "Remediation Approach",
    "Residual Risk",
    "Scheduled Completion Date",
    "Comments",
]


def render_poam(
    controls: dict[str, Control],
    matrix: dict[str, dict[str, Result]],
    waived: set[str],
    completion_days: int,
) -> list[dict[str, str]]:
    """Build POA&M rows for everything not already compliant.

    Only non-compliant controls become rows: a POA&M is a plan of action for
    open items, not an inventory of things that already pass.
    """
    due = (dt.date.today() + dt.timedelta(days=completion_days)).isoformat()
    rows: list[dict[str, str]] = []
    for host in sorted(matrix):
        for stig_id in controls:
            result = matrix[host][stig_id]
            if result.status in (STATUS_PASS, STATUS_NA):
                continue
            control = controls[stig_id]
            rows.append(
                {
                    "Control Vulnerability Description": control.title,
                    "STIG ID": stig_id,
                    "Group ID": control.group_id,
                    "Rule ID": control.rule_id,
                    "Severity": control.severity,
                    "Security Control Number": ", ".join(control.nist),
                    "Security Checks (CCI)": ", ".join(control.cci),
                    "Affected Asset": host,
                    "Status": "Risk Accepted" if stig_id in waived else "Ongoing",
                    "Remediation Approach": control.remediation,
                    "Residual Risk": control.risk,
                    "Scheduled Completion Date": due,
                    "Comments": result.detail,
                }
            )
    return rows


def write_poam(rows: list[dict[str, str]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=POAM_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def render_junit(
    controls: dict[str, Control],
    matrix: dict[str, dict[str, Result]],
    waived: set[str],
) -> ET.ElementTree:
    suites = ET.Element("testsuites", name="RHEL 8 STIG CAT II")
    for host in sorted(matrix):
        results = matrix[host]
        relevant = [results[c] for c in controls]
        failures = sum(
            1 for r in relevant if r.status in GATING_STATUSES and r.stig_id not in waived
        )
        skipped = sum(1 for r in relevant if r.status == STATUS_NA or r.stig_id in waived)
        suite = ET.SubElement(
            suites,
            "testsuite",
            name=host,
            tests=str(len(relevant)),
            failures=str(failures),
            skipped=str(skipped),
            errors="0",
        )
        for stig_id, control in controls.items():
            result = results[stig_id]
            case = ET.SubElement(
                suite,
                "testcase",
                classname=f"{host}.{control.severity.replace(' ', '')}",
                name=f"{stig_id} {control.title}"[:250],
            )
            if stig_id in waived:
                ET.SubElement(case, "skipped", message="Waived by documented risk acceptance")
            elif result.status == STATUS_NA:
                ET.SubElement(case, "skipped", message=result.detail or "Not applicable")
            elif result.status in GATING_STATUSES:
                failure = ET.SubElement(case, "failure", type=result.status, message=result.status)
                failure.text = result.detail or "No detail recorded."
    return ET.ElementTree(suites)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="stig-report",
        description="Render STIG evidence documents into compliance reports.",
    )
    parser.add_argument(
        "evidence",
        nargs="+",
        type=Path,
        help="Evidence JSON files, or directories to search recursively.",
    )
    parser.add_argument(
        "--controls",
        type=Path,
        default=Path("ansible/controls/rhel8_cat2_controls.yml"),
        help="Path to the control manifest (default: %(default)s).",
    )
    parser.add_argument("--markdown", type=Path, help="Write the Markdown summary here.")
    parser.add_argument("--poam", type=Path, help="Write the POA&M CSV here.")
    parser.add_argument("--junit", type=Path, help="Write the JUnit XML here.")
    parser.add_argument(
        "--waive",
        action="append",
        default=[],
        metavar="STIG_ID",
        help="Treat this control as risk-accepted. Repeatable. Use only with a "
        "documented acceptance; it changes the gate, not the finding.",
    )
    parser.add_argument(
        "--completion-days",
        type=int,
        default=30,
        help="Days from today for the POA&M scheduled completion date (default: %(default)s).",
    )
    parser.add_argument(
        "--exit-zero",
        action="store_true",
        help="Always exit 0. For report-only runs that must not fail the job.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        controls = load_controls(args.controls)
        evidence = load_evidence(args.evidence)
    except ReportError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2

    waived = set(args.waive)
    unknown_waivers = waived - set(controls)
    if unknown_waivers:
        sys.stderr.write(
            "error: waived controls not present in the manifest: "
            f"{', '.join(sorted(unknown_waivers))}\n"
        )
        return 2

    matrix = reconcile(evidence, controls)
    markdown = render_markdown(evidence, controls, matrix, waived)

    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(markdown, encoding="utf-8")
    else:
        sys.stdout.write(markdown + "\n")

    if args.poam:
        write_poam(render_poam(controls, matrix, waived, args.completion_days), args.poam)

    if args.junit:
        args.junit.parent.mkdir(parents=True, exist_ok=True)
        tree = render_junit(controls, matrix, waived)
        ET.indent(tree, space="  ")
        tree.write(args.junit, encoding="utf-8", xml_declaration=True)

    findings = gating_findings(matrix, waived)
    if findings:
        sys.stderr.write(
            f"{len(findings)} control(s) require action across {len(matrix)} host(s): "
            + ", ".join(sorted({f"{f.stig_id}@{f.host}" for f in findings}))
            + "\n"
        )
    return 0 if args.exit_zero or not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
