# devops-essentials-sample-app

This is a simple sample application intended to be used alongside the labs for DevOps Essentials.

## RHEL 8 STIG CAT II baseline

The repository also carries a DISA STIG remediation baseline for Red Hat
Enterprise Linux 8 (V2R8, CAT II): an Ansible role, a compliance reporter, and
the GitHub workflows that gate and evidence its use.

**29 controls implemented** of the benchmark's 314 CAT II rules. Adding more is
a matter of dropping an export into `ansible/controls/disa-exports/` and writing
a task file per control; until one exists, the control is reported as a coverage
gap and CI fails rather than quietly omitting it.

**Start here:** [`docs/STIG-CAT-II-Remediation.md`](docs/STIG-CAT-II-Remediation.md)
— the approach, the traps, and the rollout sequence.

**Execution model:** [`docs/AAP-INTEGRATION.md`](docs/AAP-INTEGRATION.md)
— how GitHub and Ansible Automation Platform divide the work.

**Per-control detail:** [`docs/CONTROL-REFERENCE.md`](docs/CONTROL-REFERENCE.md)
— generated from the DISA export; one check and one remediation per control,
with the task file that enforces each. Regenerate with
`python scripts/stig/gen_control_docs.py --write`.

```
ansible/
  controls/rhel8_cat2_controls.yml   29 CAT II controls with CCI/NIST mappings
  controls/disa-exports/             the DISA sources; add a file, never edit one
  remediate.yml                      converge a tier
  audit.yml                          read-only; non-zero exit on open findings
  roles/rhel8_stig_cat2/             one task file per STIG ID
  tests/evidence_contract.yml        pins the role/reporter schema contract
scripts/stig/
  report.py                          evidence -> Markdown, POA&M CSV, JUnit XML
  parse_disa_export.py               DISA text export -> control manifest
  gen_control_docs.py                DISA text export -> control reference doc
  gen_aap_categories.py              manifest -> per-category AAP drift audits
  package_release.py                 reproducible, checksummed transfer archive
aap/
  execution-environment.yml          pinned EE, built with ansible-builder
  configure.yml                      applies the controller config as code
  controller/                        projects, credentials, templates, RBAC
  controller/category_audits.yml     generated: one drift audit per category
.github/workflows/                   validate + AAP project sync
```

### Quick start

```bash
pip install -r scripts/stig/requirements-dev.txt
cd ansible && ansible-galaxy collection install -r requirements.yml

# Report what would change. Nothing is modified.
ansible-playbook remediate.yml --check --diff --limit rhel8_staging

# Read-only compliance audit; exits non-zero if any control is Open.
ansible-playbook audit.yml --limit rhel8_staging
```

### Local checks

```bash
yamllint -c .yamllint ansible/    # YAML style
ansible-lint                      # production profile
python -m pytest                  # reporter, parser and generator unit tests
python scripts/stig/gen_control_docs.py --check   # reference doc is current
ruff check scripts/               # Python lint
```

`ansible/inventory/` is a **sample**. Point the playbooks at a real inventory
before running them against anything.
