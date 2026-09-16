#!/usr/bin/env python3
"""Parse a DISA STIG text export into the repository's control manifest.

DISA publishes a new RHEL 8 release roughly quarterly. Each one renames rule
IDs, adds controls and sometimes changes a fix. Hand-maintaining the manifest
against that cadence is how manifests drift out of step with the benchmark the
role claims to enforce.

This reads the plain-text export (the "ALL_CAT_II.txt" style dump) and emits a
manifest skeleton. It deliberately does not overwrite the human-authored fields
- remediation, risk, notes and reboot_required encode engineering judgement
about blast radius that no parser can derive from the fix text. Run with
--merge to keep those fields from the existing manifest and surface only what
actually changed.

  python3 scripts/stig/parse_disa_export.py ALL_CAT_II.txt \
      --merge ansible/controls/rhel8_cat2_controls.yml --diff
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.stderr.write("PyYAML is required: pip install -r scripts/stig/requirements.txt\n")
    raise

# The export is label/value pairs on consecutive lines, with free-text blocks
# introduced by a "Label:" line. Fields we lift into the manifest:
LABELS = {
    "Group ID:": "group_id",
    "Rule ID:": "rule_id",
    "STIG ID:": "stig_id",
    "SRG ID:": "srg",
    "Severity:": "severity",
    "Rule Title:": "title",
}
# Free-text blocks run until the next known label.
BLOCK_LABELS = ("Discussion:", "Check Text:", "Fix Text:")
CCI_RE = re.compile(r"^(CCI-\d{6})\s*$")
NIST_RE = re.compile(r"^NIST SP 800-53(?: Revision \d)?\s*::\s*(.+?)\s*$")
RECORD_SEP_RE = re.compile(r"^_{5,}\s*$")

# Fields that carry engineering judgement, preserved across a re-parse.
CURATED_FIELDS = ("remediation", "risk", "reboot_required", "applicability", "notes")

DEFAULTS = {
    "remediation": "automated",
    "risk": "unknown",
    "reboot_required": False,
}


def parse_export(text: str) -> list[dict[str, Any]]:
    """Split the export into one dict per control, deduplicated by STIG ID."""
    controls: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    pending_label: str | None = None
    lines = text.splitlines()

    def flush() -> None:
        if current.get("stig_id"):
            controls.append(dict(current))
        current.clear()

    for raw_line in lines:
        line = raw_line.rstrip()
        if RECORD_SEP_RE.match(line):
            flush()
            pending_label = None
            continue

        if line in BLOCK_LABELS:
            pending_label = None
            continue

        if line in LABELS:
            # The value is on the following line in this export format.
            pending_label = LABELS[line]
            continue

        if pending_label:
            current[pending_label] = line.strip()
            pending_label = None
            continue

        cci_match = CCI_RE.match(line)
        if cci_match:
            current.setdefault("cci", []).append(cci_match.group(1))
            continue

        nist_match = NIST_RE.match(line)
        if nist_match:
            control_id = nist_match.group(1)
            nist = current.setdefault("nist", [])
            if control_id not in nist:
                nist.append(control_id)
            continue

    flush()

    # The exports repeat controls that satisfy several SRGs. Keep the first
    # occurrence and merge any CCI/NIST references the later copies added.
    deduped: dict[str, dict[str, Any]] = {}
    for control in controls:
        stig_id = control["stig_id"]
        if stig_id in deduped:
            existing = deduped[stig_id]
            for key in ("cci", "nist"):
                merged = list(dict.fromkeys(existing.get(key, []) + control.get(key, [])))
                if merged:
                    existing[key] = merged
        else:
            deduped[stig_id] = control
    return [deduped[k] for k in sorted(deduped)]


def load_curated(path: Path) -> dict[str, dict[str, Any]]:
    """Read the curated fields out of an existing manifest."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {
        entry["stig_id"]: {k: entry[k] for k in CURATED_FIELDS if k in entry}
        for entry in raw.get("controls", [])
        if entry.get("stig_id")
    }


def build_manifest(
    controls: list[dict[str, Any]],
    curated: dict[str, dict[str, Any]],
    benchmark: dict[str, Any],
) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for control in controls:
        entry: dict[str, Any] = {
            "stig_id": control["stig_id"],
            "group_id": control.get("group_id", ""),
            "rule_id": control.get("rule_id", ""),
            "severity": control.get("severity", "CAT II"),
            "srg": control.get("srg", ""),
            "title": control.get("title", ""),
            "cci": control.get("cci", []),
            "nist": control.get("nist", []),
        }
        entry.update(DEFAULTS)
        entry.update(curated.get(control["stig_id"], {}))
        entries.append(entry)
    return {"benchmark": benchmark, "controls": entries}


def diff_manifests(
    old: dict[str, dict[str, Any]], new: list[dict[str, Any]]
) -> tuple[list[str], list[str], list[str]]:
    """Return (added, removed, needs_review) STIG IDs."""
    new_ids = {c["stig_id"] for c in new}
    old_ids = set(old)
    added = sorted(new_ids - old_ids)
    removed = sorted(old_ids - new_ids)
    # A control carried over without curated judgement still needs a human.
    needs_review = sorted(
        c["stig_id"]
        for c in new
        if c["stig_id"] in old_ids and not old[c["stig_id"]].get("remediation")
    )
    return added, removed, needs_review


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="parse-disa-export",
        description="Convert a DISA STIG text export into a control manifest.",
    )
    parser.add_argument("export", type=Path, help="The DISA STIG text export.")
    parser.add_argument(
        "--merge",
        type=Path,
        help="Existing manifest whose curated fields should be preserved.",
    )
    parser.add_argument("--output", type=Path, help="Write the manifest here (default: stdout).")
    parser.add_argument(
        "--diff",
        action="store_true",
        help="Report added/removed controls and exit 1 if the manifest would change. "
        "Use this in CI to catch a new STIG release.",
    )
    parser.add_argument("--product", default="Red Hat Enterprise Linux 8")
    parser.add_argument("--version", default="2")
    parser.add_argument("--release", default="8")
    parser.add_argument("--benchmark-date", default="")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        text = args.export.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2

    controls = parse_export(text)
    if not controls:
        sys.stderr.write(
            "error: no controls parsed. Check that the export is the plain-text "
            "format with 'STIG ID:' / 'Rule Title:' label lines.\n"
        )
        return 2

    curated = load_curated(args.merge) if args.merge and args.merge.exists() else {}

    if args.diff:
        added, removed, needs_review = diff_manifests(curated, controls)
        for stig_id in added:
            print(f"ADDED    {stig_id}  (needs a task file and a curated risk assessment)")
        for stig_id in removed:
            print(f"REMOVED  {stig_id}  (superseded by this benchmark release)")
        for stig_id in needs_review:
            print(f"REVIEW   {stig_id}  (no remediation approach recorded)")
        if not (added or removed or needs_review):
            print(f"Manifest is in step with the export: {len(controls)} controls.")
            return 0
        return 1

    manifest = build_manifest(
        controls,
        curated,
        {
            "product": args.product,
            "version": args.version,
            "release": args.release,
            "benchmark_date": args.benchmark_date,
        },
    )
    rendered = yaml.safe_dump(manifest, sort_keys=False, width=100, allow_unicode=True)
    header = (
        "---\n"
        "# Generated by scripts/stig/parse_disa_export.py from the DISA text export.\n"
        "# Curated fields (remediation, risk, reboot_required, applicability, notes)\n"
        "# are preserved across regeneration - re-review them when a control is added.\n"
    )
    if args.output:
        args.output.write_text(header + rendered, encoding="utf-8")
    else:
        sys.stdout.write(header + rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
