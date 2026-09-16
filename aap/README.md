# Ansible Automation Platform configuration

Everything AAP needs to run this baseline, as code. Nothing here is authored in
the AAP web UI, for the same reason nothing in `ansible/` is authored on a
production host: a change made in a UI has no diff, no reviewer and no history.

```
aap/
├── execution-environment.yml     ansible-builder definition, pinned
├── requirements.yml              collections needed to APPLY this config
├── configure.yml                 playbook that applies it
└── controller/
    ├── projects.yml              GitHub -> AAP, update revision on launch
    ├── credentials.yml           credential SHELLS only; no secret material
    ├── inventories.yml           inventory and its source
    ├── job_templates.yml         5 templates + surveys
    ├── workflow_job_templates.yml  the staged rollout, with approval nodes
    ├── schedules.yml             nightly audit; nothing that writes is scheduled
    ├── notification_templates.yml
    └── rbac.yml                  organization, teams, role assignments
```

## Applying it

```bash
ansible-galaxy collection install -r aap/requirements.yml
export CONTROLLER_HOST=https://aap.example.mil
export CONTROLLER_OAUTH_TOKEN=...
ansible-playbook aap/configure.yml --check    # always review the diff first
ansible-playbook aap/configure.yml
```

## Building the execution environment

```bash
ansible-builder build -f aap/execution-environment.yml \
    -t registry.example.mil/stig/rhel8-cat2-ee:2.8.0
podman push registry.example.mil/stig/rhel8-cat2-ee:2.8.0
```

Tag it with the **benchmark version it was validated against**, not `latest`.
A job that ran green in March and red in June with no content change is almost
always an unpinned collection or a rebuilt base image.

## The five job templates

| Template | Writes to hosts | Who can launch | Notes |
| --- | --- | --- | --- |
| `STIG CAT II - Audit` | No | Operators | Read-only. The drift detector. Scheduled nightly. |
| `STIG CAT II - Remediate (Check Mode)` | No | Operators | `job_type: check` fixed on the template, not chosen in a survey. |
| `STIG CAT II - Remediate (Automated and Assisted)` | Yes | Engineers | 21 tags. Gated controls excluded by tag *and* by default-off variables. |
| `STIG CAT II - Remediate (Gated Control)` | Yes | Engineers | One gated control per launch. Behind a workflow approval node. |
| `STIG CAT II - Evidence Report` | No | Operators | Reads evidence off the fleet, renders POA&M, publishes `set_stats`. |

## Why the boundaries are where they are

**`job_type: check` is fixed on the template.** A template that can be flipped
from dry run to apply by changing a dropdown is not a dry run; it is an apply
waiting for a mistake.

**Gated controls are excluded by tag as well as by variable.** The role already
defaults them off, but a tag list is a second, independent boundary: a gated
control cannot be switched on by an extra var passed to the automated template,
because its tasks are never selected in the first place.

**One gated control per launch.** Enabling fapolicyd enforcement and USBGuard in
the same job produces a host that has lost both the ability to execute software
and its console keyboard, with a single job to debug.

**Nothing that modifies a host is scheduled.** Only the audit runs on a timer.
Remediation is always launched by a person against a change record, which the
survey makes mandatory and the role writes into the evidence document.

**Approvers hold no execute role.** An approver who can also launch can approve
their own change, which is not separation of duties, it is paperwork.

## What AAP gives you that `ansible-playbook` does not

- **Approval nodes** — a hard stop inside the automation, recorded against a
  named human, that no amount of re-running gets past.
- **Credential isolation** — the SSH key is injected at run time and never
  rendered back out, not even to the person who launched the job. With an
  external secret manager attached, rotation happens in one place.
- **RBAC with separation of duties** — launch, approve and edit are three
  different permissions held by three different teams.
- **Job artifacts** — `set_stats` from the evidence job is readable through the
  API, so a ticketing integration consumes the outcome instead of scraping logs.
- **An execution environment** — the same container image every time, so the
  run is reproducible months later when the assessor asks.
