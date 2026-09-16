"""Tests for the DISA export parser.

The export repeats controls that satisfy multiple SRGs - V-254520 appears twice
in the CAT II dump. Deduplication is the behaviour worth pinning: a duplicated
control would otherwise produce duplicate POA&M rows and a double-counted
compliance percentage.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from scripts.stig import parse_disa_export as parser

MANIFEST = Path(__file__).resolve().parents[2] / "ansible/controls/rhel8_cat2_controls.yml"

SAMPLE = """\
Red Hat Enterprise Linux 8
Version: 2 Release: 8 Benchmark Date: 01 Jul 2026
Group ID:
V-284949
Rule ID:
SV-284949r1208759
STIG ID:
RHEL-08-040222
SRG ID:
SRG-OS-000420-GPOS-00186
Severity:
CAT II
Rule Title:
RHEL 8 must log IPv4 packets with impossible addresses by default.
Discussion:
Martian packets are a sign of nefarious network activity.
Check Text:
$ sudo sysctl net.ipv4.conf.default.log_martians
Fix Text:
net.ipv4.conf.default.log_martians=1
CCI-002386
The organization defines the security safeguards.
NIST SP 800-53 Revision 4 :: SC-5

________________________________________

Red Hat Enterprise Linux 8
Group ID:
V-254520
Rule ID:
SV-254520r1069331
STIG ID:
RHEL-08-040400
SRG ID:
SRG-OS-000324-GPOS-00125
Severity:
CAT II
Rule Title:
RHEL 8 must prevent nonprivileged users from executing privileged functions.
Fix Text:
semanage login -a -s user_u <username>
CCI-002235
Prevent non-privileged users from executing privileged functions.
NIST SP 800-53 Revision 4 :: AC-6 (10)

________________________________________

Red Hat Enterprise Linux 8
Group ID:
V-254520
Rule ID:
SV-254520r1069331
STIG ID:
RHEL-08-040400
SRG ID:
SRG-OS-000324-GPOS-00125
Severity:
CAT II
Rule Title:
RHEL 8 must prevent nonprivileged users from executing privileged functions.
CCI-002235
Prevent non-privileged users from executing privileged functions.
NIST SP 800-53 Revision 5 :: AC-6 (10)
"""


def test_parses_fields_from_the_label_value_layout():
    controls = parser.parse_export(SAMPLE)
    by_id = {c["stig_id"]: c for c in controls}
    martians = by_id["RHEL-08-040222"]
    assert martians["group_id"] == "V-284949"
    assert martians["rule_id"] == "SV-284949r1208759"
    assert martians["severity"] == "CAT II"
    assert martians["title"].startswith("RHEL 8 must log IPv4 packets")
    assert martians["cci"] == ["CCI-002386"]
    assert martians["nist"] == ["SC-5"]


def test_duplicate_controls_collapse_to_one_entry():
    controls = parser.parse_export(SAMPLE)
    assert [c["stig_id"] for c in controls].count("RHEL-08-040400") == 1


def test_duplicate_controls_merge_their_nist_references():
    # Revision 4 and Revision 5 both map to AC-6 (10); it must appear once.
    by_id = {c["stig_id"]: c for c in parser.parse_export(SAMPLE)}
    assert by_id["RHEL-08-040400"]["nist"] == ["AC-6 (10)"]


def test_curated_fields_survive_regeneration():
    curated = parser.load_curated(MANIFEST)
    assert curated["RHEL-08-040400"]["remediation"] == "gated"
    assert curated["RHEL-08-040400"]["risk"] == "high"

    manifest = parser.build_manifest(parser.parse_export(SAMPLE), curated, {})
    entry = next(c for c in manifest["controls"] if c["stig_id"] == "RHEL-08-040400")
    # Parsed facts refresh; engineering judgement is preserved.
    assert entry["rule_id"] == "SV-254520r1069331"
    assert entry["remediation"] == "gated"
    assert entry["risk"] == "high"


def test_new_control_defaults_to_unreviewed_judgement():
    manifest = parser.build_manifest(parser.parse_export(SAMPLE), {}, {})
    entry = next(c for c in manifest["controls"] if c["stig_id"] == "RHEL-08-040222")
    assert entry["risk"] == "unknown"


def test_diff_flags_controls_added_by_a_new_release():
    curated = {"RHEL-08-040222": {"remediation": "automated"}}
    added, removed, _ = parser.diff_manifests(curated, parser.parse_export(SAMPLE))
    assert added == ["RHEL-08-040400"]
    assert removed == []


def test_empty_export_is_a_usage_error(tmp_path, capsys):
    path = tmp_path / "empty.txt"
    path.write_text("nothing to see here\n", encoding="utf-8")
    assert parser.main([str(path)]) == 2
    assert "no controls parsed" in capsys.readouterr().err


def test_generated_manifest_is_valid_yaml(tmp_path):
    out = tmp_path / "m.yml"
    export = tmp_path / "e.txt"
    export.write_text(SAMPLE, encoding="utf-8")
    assert parser.main([str(export), "--output", str(out)]) == 0
    loaded = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert len(loaded["controls"]) == 2
