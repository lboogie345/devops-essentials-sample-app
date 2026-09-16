# DISA STIG exports

The source of truth for this baseline. Every control the role enforces, and
every row of the generated reference, derives from the plain-text exports in
this directory.

**Add a file, do not edit one.** The tooling reads every `*.txt` here, merges
them, and deduplicates by STIG ID, so partial exports can arrive over time
without rework. Controls repeated across files are collapsed and their CCI/NIST
references merged.

```
RHEL8-V2R8-CAT_II-001.txt    15 controls
RHEL8-V2R8-CAT_II-002.txt    14 controls
```

Naming: `RHEL8-<version>-<severity>-<nnn>.txt`, numbered in upload order. The
number carries no meaning beyond keeping the merge order stable and the diffs
readable.

## After adding a file

```bash
# 1. What did it add?
python scripts/stig/parse_disa_export.py ansible/controls/disa-exports \
    --merge ansible/controls/rhel8_cat2_controls.yml --diff

# 2. Fold the new controls into the manifest, keeping curated risk judgement.
python scripts/stig/parse_disa_export.py ansible/controls/disa-exports \
    --merge ansible/controls/rhel8_cat2_controls.yml \
    --output ansible/controls/rhel8_cat2_controls.yml --benchmark-date 2026-07-01

# 3. Write a task file per added control, then regenerate the reference.
python scripts/stig/gen_control_docs.py --write
```

Until a control has a task file, the generated reference lists it under
**Coverage gap** and CI fails. That is deliberate: the benchmark should drive
the work, and an unimplemented control should be loud rather than absent.

Note: the full RHEL 8 V2R8 benchmark contains **314 CAT II rules**. This
directory holds the subset exported so far.
