# Mitigating RHEL 8 CAT II findings with Ansible and GitHub

Twenty-nine CAT II findings from the RHEL 8 STIG V2R8 exports, how each one is
remediated, and what the pipeline around it has to do so the result holds.

The full benchmark carries **314 CAT II rules**. Exports arrive here piecemeal,
so everything below is built to absorb a new one by dropping a file into
`ansible/controls/disa-exports/` - see [section 8](#8-adding-the-next-export).

The short version of the approach: **the STIG is the requirement, Ansible is the
enforcement, Git is the record, and GitHub is the control.** Each of those is
doing separate work, and skipping any of them produces a baseline that passes an
audit once and drifts by the following quarter.

---

## 1. Why not just run the fix text

Every finding in the export ships with a `Fix Text` you could paste into a shell.
Doing that has three problems that only show up later.

**It is not idempotent.** `sudo vi /etc/sysctl.d/ipv4_log_martians.conf` run
twice by two engineers produces two different files. Ansible's `sysctl` module
converges to a state; a shell command performs an action.

**It leaves no evidence.** An assessor asks when a control was applied, by whom,
and under what authorization. A shell history does not answer that. A Git commit,
a PR approval, a workflow run, and an evidence artifact do.

**It does not stay fixed.** A package update reverts `/etc/pam.d/system-auth`.
An engineer adds an include to `/etc/sudoers.d`. A new host is built from an old
image. Nothing notices until the next scan, which may be a year away. Continuous
monitoring is not an audit nicety — it is NIST 800-53 CA-7, and it is what turns
a one-time remediation into a control.

---

## 2. The findings, and what each one actually requires

**Full per-control reference: [`CONTROL-REFERENCE.md`](CONTROL-REFERENCE.md)** — one check and one remediation for every control, quoted verbatim from the
DISA export, with the CCI/NIST mapping and the task file that enforces it.

That document is **generated**, not written. `scripts/stig/gen_control_docs.py`
reads the export in `ansible/controls/disa-exports/` and renders one section per
control, so the header count ("N controls, N checks, N remediations") is computed
from the benchmark rather than asserted by a human. Drop in an export with a
different number of controls, regenerate, and the totals follow. A control present
in the export with no task file in the role is reported as a **coverage gap**
rather than quietly omitted — that omission is exactly how a document
comes to claim coverage it does not have. CI runs the generator with `--check`, so
a stale reference fails the build.

The table below is the engineering summary: the enforcement, and the trap.
"Gated" means the role can fix it but will not without organization-specific
input, because a wrong value causes an outage or an access loss.

| STIG ID | Requirement | How it is enforced | The part that bites |
| --- | --- | --- | --- |
| `RHEL-08-040221` | `net.ipv4.conf.all.log_martians=1` | `ansible.posix.sysctl` → `/etc/sysctl.d/ipv4_log_martians.conf` | `sysctl --system` honours the **lexicographically last** filename across six directories. A correct file can be overridden by a later one. |
| `RHEL-08-040222` | `net.ipv4.conf.default.log_martians=1` | same file | `default.*` applies only to interfaces created *after* the change. |
| `RHEL-08-040287` | `net.ipv4.conf.default.rp_filter=1` | `/etc/sysctl.d/ipv4_rp_filter.conf` | Strict reverse-path filtering **drops legitimate traffic** on asymmetrically routed hosts. The role sets the `default` scope only; pushing it to live interfaces is opt-in per tier. |
| `RHEL-08-020360` | `declare -xr TMOUT=600` in `/etc/profile.d/` | templated script | `-r` makes TMOUT readonly; re-sourcing `/etc/profile` in a live shell then errors. Also, a competing `TMOUT` elsewhere in `/etc/profile.d` can win — the role greps for those and reports them. |
| `RHEL-08-030655` | audit watches on `/etc/cron.d`, `/var/spool/cron` | rules file + `augenrules --load` | If auditd is in **immutable mode** (`-e 2`), new rules do not reach the running kernel until reboot. Reporting this host as compliant would be false. The role reports `Open` with `reboot_required`. |
| `RHEL-08-010455` | sudo elevates SELinux context | sudoers drop-in, `visudo` validated | **Gated.** Needs an org-defined admin group. Conflicting `TYPE=`/`ROLE=` entries elsewhere are a finding by themselves. |
| `RHEL-08-020035` | `StopIdleSessionSec=600` | `/etc/systemd/logind.conf` | Only RHEL ≥ 8.7. Not applicable on cloud hosts already satisfying V-244525. Both are recorded as `Not_Applicable`, never silently skipped. |
| `RHEL-08-010358` | mail transport installed | `dnf` install `mailx` (or `s-nail`) | Installing the client satisfies the *check*; it does not mean mail reaches the ISSO. The relay is a separate, real piece of work. |
| `RHEL-08-010019` | vendor GPG keys installed, fingerprints match | restore key file from `redhat-release`, `rpm --import`, assert fingerprints | Automation must **never fetch a signing key over the network** to satisfy this — that inverts the control. Fingerprints are pinned in `defaults/main.yml`. |
| `RHEL-08-040400` | users mapped to confined SELinux users | `community.general.selogin` | **Gated, highest blast radius.** `sysadm_u` blocks SSH login unless `ssh_sysadm_login` is on. Remapping `__default__` to `user_u` changes every unmapped account, including future ones. |
| `RHEL-08-040321` | `multi-user.target` default | `systemctl set-default` | Needs a reboot. Hosts with a documented GUI requirement are exempted **with the approval reference recorded**, so the artifact shows an approved deviation rather than a gap. |
| `RHEL-08-020104` | pwquality `retry = 3` | `/etc/security/pwquality.conf` + drop-in reconciliation | `/etc/security/pwquality.conf.d/*.conf` is read *after* the main file and wins. Setting only the main file leaves a host that passes one grep and fails the other. |
| `RHEL-08-020101` | `pam_pwquality.so` in `system-auth` | custom **authselect** profile | See below. This is the one most remediation scripts get wrong. |
| `RHEL-08-010385` | no `pam_succeed_if` in `/etc/pam.d/sudo` | `lineinfile state=absent` | Removing the bypass makes sudo start prompting for a password. Any automation that escalated through it breaks at that moment. |
| `RHEL-08-010379` | only `#includedir /etc/sudoers.d` | `lineinfile` + `visudo -cf` validation | Nested includes are **reported, not deleted**. One of them may be the file granting the automation its own sudo rights. |
| `RHEL-08-010490` | SSH private host keys mode 0600 | `find`, then `file` mode | The glob must exclude `*.pub`. Tightening the public keys breaks host key verification for every client. |
| `RHEL-08-020017` | faillock tally persists a reboot | `dir =` in `faillock.conf` | The default tally lives under `/run` and is wiped at boot, so an attacker just waits for a reboot. The role refuses a `/run` path. |
| `RHEL-08-010731` | Home dir files mode 0750 or less | `chmod g-w,o-rwx` | A literal `chmod 0750` **adds** the execute bit to data files - a privilege escalation performed in the name of hardening. Clearing `0027` is a strict reduction. |
| `RHEL-08-010741` | Home dir files group-owned by an owner's group | scan + optional `chgrp` | Any group the user belongs to is compliant, not just the private group. ISSO-documented sharing exists, so this reports by default. |
| `RHEL-08-020352` | umask 077 for interactive users | scan + optional removal | "Less restrictive than 077" is a bitmask test, not a string compare. Implemented in POSIX awk on purpose: gawk's `and()`/`strtonum()` abort under mawk/busybox, and the scan would then find nothing and report compliant. |
| `RHEL-08-010590` | `noexec` on home filesystems | `mount` module, **gated** | If homes are on `/`, the check text makes it an automatic finding that configuration cannot fix. A bad `/etc/fstab` leaves a host unbootable. |
| `RHEL-08-020320` | No unnecessary accounts | enumerate, **gated** | The role never runs `userdel` on its own. "Unnecessary" is defined by a document automation does not hold; deleting accounts it cannot authorize is a DoS with a compliance justification. |
| `RHEL-08-040030` | Ports/protocols match the PPSM CAL | evidence only, **manual** | The fix text contains no command. Closing a port the CLSA authorizes breaks a mission service; opening one it forbids is a new finding. Always reports Open. |
| `RHEL-08-040137` | fapolicyd deny-all allow listing | staged, **gated** | The STIG's own discussion: "Improper configuration may render the system nonfunctional." Not namespace-aware, so it breaks containers. Enforcement is a *second* flag beyond enabling the control. |
| `RHEL-08-040140` | USBGuard blocks peripherals | policy + service, **gated** | Starting usbguard with no policy "will immediately prevent any access over a usb device such as a keyboard" - a console lockout. VMs with no USB devices are detected as Not_Applicable. |
| `RHEL-08-020250` | Smart card logon | authselect `with-smartcard`, **gated** | Same authselect trap as `RHEL-08-020101`. Enabling it without working CAC infrastructure removes interactive access to the host. |
| `RHEL-08-020090` | PKI certificate-to-account mapping | `certmap`, **gated** | A wrong certmap does not fail loudly; it maps certificates to the *wrong* accounts. No default is safe. |
| `RHEL-08-010400` | Certificate status checking (OCSP) | `sssd.conf`, guarded | Guarded on `sssd.conf` already existing. Creating one just to hold the line yields a host that passes the grep while doing no PKI auth - a compliance record for a control that is not in force. |
| `RHEL-08-010090` | PKI path to a DoD trust anchor | verify, deploy from vetted source | The fix text says fetch from cyber.mil. Automation must **not**: pulling a trust anchor over the network is the attack this control prevents. |

### A note on the four PKI/MFA controls

`RHEL-08-010090`, `-010400`, `-020090` and `-020250` all carry the same escape
in their check text: *"If the System Administrator demonstrates the use of an
approved alternate multifactor authentication method, this requirement is not
applicable."* Setting `stig_mfa_alternate: true` with a reference records all
four as Not_Applicable with that reference attached, instead of leaving four
permanent Open findings nobody can close.

### The authselect trap (`RHEL-08-020101`, `RHEL-08-020250`)

On RHEL 8, `/etc/pam.d/system-auth` is **generated**. Editing it with `lineinfile`
appears to work — the grep in the check text passes — and then:

- the next `authselect apply-changes`, package update, or `authselect select`
  regenerates the file and the edit vanishes;
- `authselect check` starts reporting the file as modified, which is its own
  finding.

The durable fix is to own a custom profile:

```bash
authselect create-profile stig -b sssd --symlink-meta
# edit /etc/authselect/custom/stig/system-auth
authselect select custom/stig <existing features> --force
authselect apply-changes -b
```

The role does exactly this, preserving the features already selected, and falls
back to a direct edit only when authselect is genuinely not in use.
`RHEL-08-020250` (smart card logon) goes through the same mechanism via
`authselect enable-feature with-smartcard`, for the same reason.

---

## 3. How the Ansible is structured, and why

```
ansible/
├── ansible.cfg
├── requirements.yml              # collections pinned to a range
├── controls/
│   ├── rhel8_cat2_controls.yml   # the manifest: 29 controls, CCI, NIST, risk
│   └── disa-exports/             # the DISA sources everything derives from
├── inventory/group_vars/         # which controls are on, per tier
├── remediate.yml                 # converge
├── audit.yml                     # read-only, fails on open findings
└── roles/rhel8_stig_cat2/
    └── tasks/
        ├── RHEL-08-010019.yml    # one file per control
        ├── ...
        ├── record.yml            # appends a CKL-vocabulary result
        └── evidence.yml          # writes the per-host evidence document
```

**One task file per STIG ID.** A reviewer diffing a PR sees exactly which
control changed. `git log --follow ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-040287.yml`
is the control's history. Tags mean `--tags RHEL-08-040287` runs one control.

**A control manifest separate from the tasks.** The manifest carries the CCI and
NIST mappings, the risk rating, and the remediation approach. The POA&M is
generated from it, so the assessment package and the automation cannot disagree.

**Every control records a result.** `record.yml` appends a CKL-vocabulary status
— `NotAFinding`, `Open`, `Not_Applicable`, `Not_Reviewed` — with a detail string.
This matters more than it looks: a task that is `ok` in Ansible might have been
skipped, and a task that is `changed` might have moved a comment. Task status is
a statement about execution; the recorded result is a statement about *control
state*, which is what the assessor is entitled to.

**Absence is never a pass.** A control declared in the manifest but not evaluated
on a host is reported `Not_Reviewed` and gates the pipeline alongside `Open`. A
disabled flag or a silently false `when:` is exactly the failure mode that
produces a clean report over a non-compliant fleet.

**Gated controls default to off and report `Open`.** They do not report compliant
and they do not vanish. The three highest-risk controls — sudo SELinux elevation,
SELinux user mappings, and anything that could revoke administrative access —
require the organization to supply data before they run.

### Running it

```bash
cd ansible
ansible-galaxy collection install -r requirements.yml

# 1. See what would change. Always first.
ansible-playbook remediate.yml --check --diff --limit rhel8_staging

# 2. Converge one control at a time while you build confidence.
ansible-playbook remediate.yml --limit rhel8_staging --tags RHEL-08-040221

# 3. Converge the tier, in rolling batches.
ansible-playbook remediate.yml --limit rhel8_staging

# 4. Prove it, read-only. Non-zero exit if anything is Open.
ansible-playbook audit.yml --limit rhel8_staging
```

`remediate.yml` uses `serial: 25%` and `max_fail_percentage: 0` so a bad control
stops the batch instead of walking across the estate.

---

## 4. The Python layer

Two scripts, each solving a problem that recurs every quarter.

**`scripts/stig/report.py`** turns the per-host evidence documents into a Markdown
summary for the GitHub job summary, a POA&M CSV for the assessment package, and
JUnit XML so the pipeline can gate. It exits 1 on open findings, which makes it
usable directly as the gate rather than needing a wrapper.

```bash
python scripts/stig/report.py evidence/ \
  --controls ansible/controls/rhel8_cat2_controls.yml \
  --markdown summary.md --poam poam.csv --junit junit.xml
```

**`scripts/stig/parse_disa_export.py`** parses the DISA text export into the
manifest. DISA publishes roughly quarterly; each release renames rule IDs and can
add controls. Run with `--diff` in CI and the pipeline tells you a new control
appeared before an auditor does:

```bash
python scripts/stig/parse_disa_export.py ansible/controls/disa-exports/RHEL8-V2R8-CAT_II.txt \
  --merge ansible/controls/rhel8_cat2_controls.yml --diff
```

It preserves the curated fields — `remediation`, `risk`, `reboot_required`,
`notes` — because those encode judgement about blast radius that no parser can
derive from a fix text. A newly added control arrives with `risk: unknown`, which
is a prompt for a human, not a default to ship.

Note that the export in this repository contains V-254520 **twice**. The parser
deduplicates and merges the NIST references; a naive parse would double-count it
in every compliance percentage and produce duplicate POA&M rows.

---

## 5. The GitHub layer

Git gives you history. GitHub gives you *control* — and the difference is where
most of the compliance value sits.

> **Execution runs in Ansible Automation Platform.** GitHub decides what the
> baseline *is*; AAP decides what runs, where, by whom and with whose approval.
> The full split, the five job templates, the approval model and the RBAC are in
> [`AAP-INTEGRATION.md`](AAP-INTEGRATION.md). The GitHub Actions workflows that
> touched hosts directly are superseded and disabled; what remains is the
> validation gate and a project-sync trigger.

| Concern | Mechanism |
| --- | --- |
| Peer review of security content | `CODEOWNERS` requiring security engineering on the role, manifest, and inventory group_vars |
| Change authorization (CM-3) | `environment: stig-rhel8_prod` with required reviewers — the apply job blocks until a human approves |
| Separation of duties | Author cannot self-approve; environment reviewers are a different team from the PR author |
| No unreviewed path to production | Branch protection: no force push, required status checks, required Code Owner review |
| Audit trail (AU-12) | Commit history + PR approvals + workflow run logs + evidence artifacts at 90-day retention |
| Continuous monitoring (CA-7) | Nightly read-only audit that opens one issue on drift and closes it when clean |
| Secret handling | SSH key in an **environment** secret, not a repository secret, so a fork PR cannot reach it; host keys supplied rather than disabling `host_key_checking` |

Three workflows:

- **`stig-validate.yml`** — every PR. Lint, unit tests, playbook syntax, the
  evidence-schema contract test, and benchmark drift. Touches no hosts.
- **`stig-remediate.yml`** — manual dispatch only, with a tier choice, a change
  ticket input, and `dry_run` defaulting to **true**. An unattended push that
  rewrites sudoers and PAM across a fleet is not a pipeline.
- **`stig-drift.yml`** — nightly audit. Opens *one* issue and updates it; a new
  issue every night trains people to ignore the notification, which defeats the
  control.

`.github/workflows/README.md` lists the repository settings these depend on —
environments, scoped secrets, the self-hosted runner label, branch protection,
and labels. Without those the workflows fail, or silently do nothing useful.

### The contract test

The seam most likely to fail quietly is between the role and the reporter. Rename
a key in `record.yml` and nothing errors — the reporter keeps running and reports
every control `Not_Reviewed`. That failure *looks like a compliance result*,
which is the worst kind of bug here.

`ansible/tests/evidence_contract.yml` runs the role's own `record.yml` and
`evidence.yml` on the runner with synthetic results; CI then feeds the output to
the reporter and asserts it parses and yields 15 controls. Schema drift fails the
build instead of quietly producing a clean report.

---

## 6. Rollout sequence

1. **Merge the content.** Nothing is applied by merging; the apply job is manual.
2. **Dry run staging.** `stig-remediate` with `dry_run: true`. Read the diff.
3. **Apply staging.** Then run `stig-drift` manually against staging.
4. **Soak.** Let staging run for a full change window. The controls that surface
   problems are `RHEL-08-010385` (sudo starts prompting), `RHEL-08-020360`
   (readonly TMOUT), and `RHEL-08-040287` (asymmetric routing).
5. **Enable the gated controls on staging only**, one at a time, in their own
   PRs with the org data.
6. **Production, in batches**, with the environment approval and a change record.
7. **Turn on the nightly drift job** and treat its issue as a real ticket.

## 8. Adding the next export

The benchmark has 314 CAT II rules and the exports arrive a few at a time. The
workflow is the same every time, and the pipeline tells you what it needs:

```bash
# 1. Drop the file in. Never edit an existing one - add a new file.
cp ~/Downloads/ALL_CAT_II.txt ansible/controls/disa-exports/RHEL8-V2R8-CAT_II-003.txt

# 2. What did it add? Controls repeated across files are deduplicated.
python scripts/stig/parse_disa_export.py --merge ansible/controls/rhel8_cat2_controls.yml --diff
#    ADDED  RHEL-08-0xxxxx  (needs a task file and a curated risk assessment)

# 3. Write one task file per added control, curate its manifest entry, then:
python scripts/stig/gen_control_docs.py --write
#    Wrote docs/CONTROL-REFERENCE.md: N controls, N checks, N remediations.
```

Three properties make this safe to do incrementally:

- **The tools read the directory, not a file.** Adding an export needs no code
  change and no argument to remember.
- **An unimplemented control is loud.** Until it has a task file the generated
  reference lists it under *Coverage gap*, the header count shows
  `Implemented by the role: N of M`, and CI fails on both the manifest drift and
  the stale document. The benchmark drives the work.
- **Curated judgement survives regeneration.** `remediation`, `risk`,
  `reboot_required`, `applicability` and `notes` are preserved when the manifest
  is rebuilt; a newly added control arrives as `risk: unknown`, which is a
  prompt for a human rather than a default to ship.

Current split across the 29: **11 automated, 8 assisted, 9 gated, 1 manual.**
As the set grows, expect that ratio to hold or tilt further toward gated - the
controls that are trivial to automate tend to be the ones already done.

## 9. What this does not do

Stated plainly, because a compliance tool that overstates its coverage is worse
than no tool:

- It does **not** replace a SCAP scan. `oscap` with the DISA benchmark is the
  authoritative check; this enforces and evidences, it does not certify.
- `RHEL-08-010358` installs a mail client. It does not prove mail reaches the
  ISSO, which needs a working relay and a tested alert path.
- `RHEL-08-040400` cannot know your authorized-user list. An assessor compares
  the mappings against that list; automation can only apply what it is given.
- `RHEL-08-010019` cannot recover a host whose key file is missing and whose
  repos are unreachable. That one needs installation media.
- There is no Molecule scenario yet. The controls that matter most —
  authselect, auditd immutable mode, SELinux mappings — need a real RHEL 8 VM,
  not a container, so a `libvirt`/EC2 Molecule driver against a UBI-based image
  is the honest next step rather than a container scenario that would pass
  without exercising them.
