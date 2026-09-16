#!/usr/bin/env python3
"""Generate per-category AAP drift-audit templates and schedules.

Monitoring drift per security category needs one schedulable, separately
notifiable unit per category. Hand-maintaining nine near-identical job
templates is how a category silently stops being monitored: someone adds a
control in a new category, nobody adds the template, and the category reports
clean forever because nothing ever looks at it.

So the templates are generated from the manifest. Add a control in a new
category, regenerate, and the category gets its own audit, its own schedule and
its own notification. CI runs this with --check, so a missing one fails the
build rather than going unnoticed.

Each template is read-only: it runs audit.yml with `--tags cat_<category>`, and
the reporter is scoped with `--category <category>` so out-of-scope controls
neither count toward the totals nor gate the run.

  python scripts/stig/gen_aap_categories.py --write
  python scripts/stig/gen_aap_categories.py --check
"""

from __future__ import annotations

import argparse
import difflib
import re
import sys
from collections.abc import Sequence
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.stderr.write("PyYAML is required: pip install -r scripts/stig/requirements.txt\n")
    raise

DEFAULT_MANIFEST = Path("ansible/controls/rhel8_cat2_controls.yml")
DEFAULT_OUTPUT = Path("aap/controller/category_audits.yml")

# Schedules are staggered so nine notifications do not arrive in the same
# minute; a burst of simultaneous alerts gets triaged as one alert.
FIRST_RUN_HOUR = 5
STAGGER_MINUTES = 20
TIMEZONE = "America/New_York"


def family_of(control: dict) -> str:
    for ref in control.get("nist") or []:
        match = re.match(r"([A-Z]{2})-", ref)
        if match:
            return match.group(1)
    return "ZZ"


def categories(manifest_path: Path) -> dict[str, dict]:
    raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    grouped: dict[str, dict] = {}
    for control in raw["controls"]:
        entry = grouped.setdefault(
            control["category"], {"ids": [], "families": set(), "gated": 0, "manual": 0}
        )
        entry["ids"].append(control["stig_id"])
        entry["families"].add(family_of(control))
        if control.get("remediation") == "gated":
            entry["gated"] += 1
        if control.get("remediation") == "manual":
            entry["manual"] += 1
    return dict(sorted(grouped.items()))


def rrule(index: int) -> str:
    total = FIRST_RUN_HOUR * 60 + index * STAGGER_MINUTES
    return (
        f"DTSTART;TZID={TIMEZONE}:20260101T{total // 60:02d}{total % 60:02d}00 "
        "RRULE:FREQ=DAILY;INTERVAL=1"
    )


def render(grouped: dict[str, dict]) -> str:
    templates = []
    schedules = []
    associations = []

    for index, (category, meta) in enumerate(grouped.items()):
        name = f"STIG CAT II - Drift: {category}"
        note = f"{len(meta['ids'])} control(s), NIST family {', '.join(sorted(meta['families']))}."
        if meta["gated"]:
            note += (
                f" {meta['gated']} gated control(s) report Open until the organization "
                "supplies their data - expect this category to stay red until they are "
                "enabled or formally risk-accepted."
            )
        if meta["manual"]:
            note += (
                f" {meta['manual']} manual control(s) have no automatable fix and always "
                "report Open; closure is a documented human comparison."
            )

        templates.append(
            {
                "name": name,
                "job_type": "run",
                "organization": "Platform Security",
                "project": "RHEL 8 STIG CAT II",
                "playbook": "ansible/audit.yml",
                "inventory": "RHEL 8 Fleet",
                "execution_environment": "stig-rhel8-cat2-ee",
                "credentials": ["RHEL 8 Fleet - Machine", "RHEL 8 Fleet - Vault"],
                "ask_limit_on_launch": True,
                "become_enabled": True,
                "job_tags": f"cat_{category}",
                "extra_vars": {"stig_target": "rhel8", "stig_category": category},
                "description": f"Read-only drift audit scoped to {category}. {note}",
            }
        )
        schedules.append(
            {
                "name": f"STIG CAT II - Daily drift: {category}",
                "unified_job_template": name,
                "rrule": rrule(index),
                "description": f"Daily read-only drift check for {category}.",
                "enabled": True,
            }
        )
        associations.append({"name": name, "notification_on_failure": ["STIG - Drift webhook"]})

    header = (
        "---\n"
        "# GENERATED FILE - DO NOT EDIT BY HAND.\n"
        "# Regenerate with: python scripts/stig/gen_aap_categories.py --write\n"
        "# Source: ansible/controls/rhel8_cat2_controls.yml (the `category` field)\n"
        "#\n"
        "# One read-only drift audit per security category, each separately\n"
        "# schedulable and separately notifiable. This is what makes drift\n"
        "# monitoring per category rather than one fleet-wide pass/fail: a\n"
        "# category that was clean yesterday and is red today names the area that\n"
        "# is degrading and the team that owns it.\n"
        "#\n"
        "# Every template here is read-only. None of them can modify a host.\n"
        "#\n"
        "# The keys are namespaced (stig_category_*) rather than controller_*:\n"
        "# aap/configure.yml loads this directory with include_vars, which would\n"
        "# silently overwrite the hand-written controller_templates rather than\n"
        "# add to them. configure.yml concatenates them explicitly.\n"
        f"# Schedules are staggered {STAGGER_MINUTES} minutes apart from "
        f"{FIRST_RUN_HOUR:02d}:00 {TIMEZONE}\n"
        "# so that nine simultaneous alerts do not get triaged as one.\n"
    )

    class Dumper(yaml.SafeDumper):
        # Signatures are PyYAML's; the unused arguments are part of the contract.
        def ignore_aliases(self, data):  # noqa: ARG002
            return True

        def increase_indent(self, flow=False, indentless=False):  # noqa: ARG002
            # yamllint (and humans) expect list items indented under their key.
            return super().increase_indent(flow, False)

    body = yaml.dump(
        {
            # Namespaced, NOT controller_templates/controller_schedules.
            # aap/configure.yml loads the whole controller/ directory with
            # include_vars, which silently overwrites same-named variables - the
            # last file loaded would replace job_templates.yml's set entirely and
            # the core templates would vanish with no error. configure.yml
            # concatenates these onto the hand-written lists explicitly.
            "stig_category_templates": templates,
            "stig_category_schedules": schedules,
            "stig_category_notifications": associations,
        },
        Dumper=Dumper,
        sort_keys=False,
        width=88,
        default_flow_style=False,
        allow_unicode=True,
    )
    return header + body


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="gen-aap-categories",
        description="Generate per-category AAP drift audits from the control manifest.",
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true", help="Exit 1 with a diff if stale.")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        grouped = categories(args.manifest)
    except (OSError, yaml.YAMLError, KeyError) as exc:
        sys.stderr.write(f"error: cannot read {args.manifest} ({exc})\n")
        return 2
    if not grouped:
        sys.stderr.write(f"error: no categories found in {args.manifest}\n")
        return 2

    rendered = render(grouped)

    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.exists() else ""
        if current == rendered:
            print(f"{args.output} is up to date ({len(grouped)} categories).")
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
        print(f"Wrote {args.output}: {len(grouped)} categories.")
        return 0

    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
