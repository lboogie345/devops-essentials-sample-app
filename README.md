# devops-essentials-sample-app

This is a simple sample application intended to be used alongside the labs for DevOps Essentials.

## RHEL 8 STIG CAT II baseline

The repository also carries a DISA STIG remediation baseline for Red Hat
Enterprise Linux 8 (V2R8, CAT II): an Ansible role, a compliance reporter, and
the GitHub workflows that gate and evidence its use.

**Start here:** [`docs/STIG-CAT-II-Remediation.md`](docs/STIG-CAT-II-Remediation.md)

```
ansible/
  controls/rhel8_cat2_controls.yml   15 CAT II controls with CCI/NIST mappings
  controls/disa-exports/             the DISA source the manifest derives from
  remediate.yml                      converge a tier
  audit.yml                          read-only; non-zero exit on open findings
  roles/rhel8_stig_cat2/             one task file per STIG ID
  tests/evidence_contract.yml        pins the role/reporter schema contract
scripts/stig/
  report.py                          evidence -> Markdown, POA&M CSV, JUnit XML
  parse_disa_export.py               DISA text export -> control manifest
.github/workflows/                   validate, remediate (gated), drift detection
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
python -m pytest                  # reporter and parser unit tests
ruff check scripts/               # Python lint
```

`ansible/inventory/` is a **sample**. Point the playbooks at a real inventory
before running them against anything.
