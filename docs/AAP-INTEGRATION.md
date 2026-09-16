# GitHub and Ansible Automation Platform: how the 29 controls get mitigated

Two systems, two jobs, and the split is the point.

**GitHub decides what the baseline *is*.** Content, review, risk classification,
and the merge gate. Nothing reaches a host that has not been through a pull
request under CODEOWNERS.

**AAP decides what actually *runs*, where, by whom, and with whose approval.**
Execution, credentials, RBAC, approval nodes, scheduling and evidence.

Neither can do the other's job. GitHub Actions cannot hold a machine credential
for a classified fleet or enforce separation of duties between the person who
writes a control and the person who authorizes it against production. AAP has no
code review, no diff, and no history for content authored in its UI.

Per-control detail — the check, the fix text, the task file, the job template,
the approval requirement and the tunables — is in
**[`CONTROL-REFERENCE.md`](CONTROL-REFERENCE.md)**, generated from the benchmark
so it cannot drift from what is implemented.

---

## 1. The path a control takes

```
   DISA export                  GitHub                         AAP
   ───────────                  ──────                         ───
   ALL_CAT_II.txt
        │
        │  parse_disa_export.py --diff
        ▼
   manifest entry  ──►  PR: task file + curated risk
                              │
                              │  stig-validate must pass:
                              │    ansible-lint (production)
                              │    yamllint
                              │    playbook syntax
                              │    evidence-schema contract
                              │    benchmark drift
                              │    AAP boundary tests
                              │    generated-doc staleness
                              │
                              │  CODEOWNERS review
                              ▼
                        merge to main ──────────►  Project sync
                                                   (revision on launch)
                                                        │
                                          ┌─────────────┴─────────────┐
                                          ▼                           ▼
                                   Audit template            Staged Rollout workflow
                                   (read-only,               audit → check → APPROVE
                                    nightly)                  → apply staging → verify
                                                              → APPROVE → prod → evidence
                                                        │
                                                        ▼
                                              evidence document per host
                                                        │
                                                        ▼
                                              POA&M + JUnit + set_stats
```

## 2. What each system is responsible for

| Concern | Owner | Mechanism |
| --- | --- | --- |
| What a control does | GitHub | Task file per STIG ID, reviewed under CODEOWNERS |
| Whether a control is safe to automate | GitHub | `remediation` + `risk` in the manifest, set by a human in review |
| Content correctness | GitHub | `stig-validate` on every PR; nothing merges red |
| Who may run it | AAP | Teams: Operators (read-only), Engineers (apply), Approvers (approve only) |
| Whether this run is authorized | AAP | Workflow approval nodes + a mandatory change-record survey field |
| What credentials it uses | AAP | Machine/Vault credentials, injected at run time, never rendered back |
| Which hosts | AAP | Inventory + `stig_target`, with `--limit` asked at launch |
| Reproducibility | Both | Pinned collections in git; pinned execution environment in AAP |
| Evidence | AAP | Per-host JSON on the host, collected into a POA&M by the report template |
| Continuous monitoring | AAP | Nightly audit schedule; nothing that writes is ever scheduled |

## 3. The five job templates, and the boundary between them

| Template | Writes | Launchable by | Controls in scope |
| --- | --- | --- | --- |
| `STIG CAT II - Audit` | No | Operators | All 29 |
| `STIG CAT II - Remediate (Check Mode)` | No | Operators | All 29, `job_type: check` fixed |
| `STIG CAT II - Remediate (Automated and Assisted)` | Yes | Engineers | 19, by explicit tag list |
| `STIG CAT II - Remediate (Gated Control)` | Yes | Engineers | 9, one per launch, approval-gated |
| `STIG CAT II - Evidence Report` | No | Operators | Reads evidence, renders POA&M |

The 19/9/1 split is the manifest's own classification, not a second opinion:

- **19 automated + assisted** — safe to apply as a batch behind a tier approval.
- **9 gated** — each can take a host offline in a different way, so each gets its
  own launch and its own approval node.
- **1 manual** (`RHEL-08-040030`, PPSM) — has no automatable fix at all, so it
  appears in no remediation template. The audit template gathers its evidence.

**This boundary is tested, not trusted.** `scripts/tests/test_aap_config.py`
fails the build if a gated control appears in the automated template's tag list,
if the gated survey stops offering every gated control, if a writing template
gets scheduled, or if the Approvers team ever gains an execute role.

That test exists because the first version of this config got it wrong:
`RHEL-08-040321` is gated — it changes the default systemd target and needs a
reboot and ISSO sign-off — and it was sitting in the automated template's tag
list where no approval node would ever see it.

## 3a. Drift monitoring by security category

A single fleet-wide pass/fail tells an ISSO nothing they can act on. "Three open
findings" does not say whether the estate is holding steady or whether privilege
escalation quietly degraded this week.

So every control carries a **security category**, and each category gets its own
read-only drift audit, its own daily schedule and its own notification:

| Category | NIST family | Controls | Ansible tag |
| --- | --- | ---: | --- |
| account-management | CM | 1 | `cat_account-management` |
| audit-and-accountability | AU, CM | 2 | `cat_audit-and-accountability` |
| authentication | AC, CM, IA | 7 | `cat_authentication` |
| filesystem-and-permissions | CM | 5 | `cat_filesystem-and-permissions` |
| network-hardening | CM, SC | 4 | `cat_network-hardening` |
| privilege-escalation | AC, CM, IA | 4 | `cat_privilege-escalation` |
| session-management | SC | 2 | `cat_session-management` |
| software-integrity | CM | 2 | `cat_software-integrity` |
| system-services-and-devices | CM, IA | 2 | `cat_system-services-and-devices` |

The NIST family is **derived** from each control's own 800-53 mapping, not
stored separately, so the two cannot disagree.

**The templates are generated, not hand-written.**
`scripts/stig/gen_aap_categories.py` renders
`aap/controller/category_audits.yml` from the manifest. Add a control in a new
category and that category gets its own audit automatically. Hand-maintaining
nine near-identical templates is precisely how a category stops being monitored:
someone adds a control, nobody adds the template, and the category reports clean
forever because nothing ever looks at it. CI runs the generator with `--check`.

Each audit is read-only, runs `audit.yml --tags cat_<category>`, and scopes the
reporter with `--category <category>` so controls outside the category neither
count toward the totals nor gate the run. Schedules are staggered 20 minutes
apart from 05:00 — nine alerts arriving in the same minute get triaged as one.

The report renders a posture table per category:

```
| Category                   | NIST family | Controls | Score | Open / Not reviewed  | Hosts |
| ❌ privilege-escalation     | AC, CM, IA  |        4 |   62% | RHEL-08-010385, ...  |     2 |
| ✅ session-management       | SC          |        2 |  100% | none                 |     0 |
```

Two deliberate choices in that table, worth understanding before you quote it:

- **Not_Applicable counts toward the score.** A control that does not apply to a
  host is not a gap in that host's posture. Counting it as one makes every
  category look permanently broken and trains people to ignore the number.
- **The score is waiver-blind; the red/green is not.** A documented risk
  acceptance means nobody has to act, so the category is not red. It does not
  make the weakness go away, so the percentage does not improve. Otherwise
  accepting risk would look identical to fixing it — which is exactly the
  confusion an assessor is trained to look for.

## 4. Defence in depth on the gated controls

A gated control has to get through four independent things before it changes a
production host:

1. **The role default is `false`.** `stig_040137_enforce`, `stig_040400_enabled`
   and the rest ship off. A run that forgets to enable one does nothing.
2. **The tag list excludes it.** Even if a variable were set in inventory, the
   automated template never selects those tasks.
3. **A survey demands the specifics.** Control ID, tier, batch size, change
   record, and an explicit "staging soak completed" confirmation.
4. **An approval node blocks the run** until a named human on the Approvers team
   releases it — and that team holds no execute role, so they cannot approve
   their own change.

Removing any one of those still leaves three. That is the point of layering them
rather than picking the strongest.

## 5. Credentials

No secret material is in this repository, and none should be.
`aap/controller/credentials.yml` defines credential *shells* — name, type,
organization, and the non-secret inputs like the username and become method.

AAP holds the values, encrypted, and never renders them back out — not to the
person who launched the job, not in job output, not through the API. Where you
have an external secret manager (CyberArk, HashiCorp Vault, Azure Key Vault,
Thycotic), attach it as a credential lookup source instead of pasting a key, so
rotation happens in one place.

One operational detail worth flagging: the automation account needs working
`sudo` with a password or an SSH certificate — **not** a passwordless bypass,
because `RHEL-08-010385` removes exactly that kind of bypass from
`/etc/pam.d/sudo`. An automation account that depends on it will authenticate
successfully right up until the moment this baseline runs, and then stop.

## 6. Where GitHub Actions still earns its place

Execution moved to AAP; validation did not. `stig-validate` runs on every pull
request and touches no host:

- `ansible-lint` at the production profile and `yamllint`
- `--syntax-check` on all three playbooks
- the evidence-schema contract test (role output vs. reporter input)
- benchmark drift (manifest vs. the committed DISA exports)
- generated-document staleness (`gen_control_docs.py --check`)
- the AAP boundary tests above

`stig-sync-aap.yml` triggers a project sync on merge to `main`, so the
controller picks up approved content without waiting for the next launch.

The two host-touching Actions workflows from the pre-AAP design
(`stig-remediate.yml`, `stig-drift.yml`) are **superseded**. They are kept in the
repository, disabled, for sites running this without AAP. Running both at once
means two schedulers converging the same fleet with different credentials and no
shared approval record — pick one.

## 7. Setting it up

```bash
# 1. Build and push the execution environment.
ansible-builder build -f aap/execution-environment.yml \
    -t registry.example.mil/stig/rhel8-cat2-ee:2.8.0
podman push registry.example.mil/stig/rhel8-cat2-ee:2.8.0

# 2. Apply the controller configuration.
ansible-galaxy collection install -r aap/requirements.yml
export CONTROLLER_HOST=https://aap.example.mil
export CONTROLLER_OAUTH_TOKEN=...
ansible-playbook aap/configure.yml --check     # review the diff first
ansible-playbook aap/configure.yml

# 3. Replace the placeholder inventory source with your real one.
#    ansible/inventory/ is a sample that exists so CI can resolve against it.
```

Then, in order:

1. Launch **`STIG CAT II - Audit`** against `rhel8_staging`. Expect findings —
   that is the baseline measurement.
2. Launch **`STIG CAT II - Remediate (Check Mode)`**. Read the diff.
3. Launch the **`STIG CAT II - Staged Rollout`** workflow. It stops at the
   staging approval node.
4. Soak staging for a full change window. The controls that surface problems
   first are `RHEL-08-010385` (sudo starts prompting), `RHEL-08-020360`
   (readonly TMOUT) and `RHEL-08-040287` (asymmetric routing).
5. Release the production approval node.
6. Enable the nightly audit schedule and treat its failures as tickets.
7. Stage the 9 gated controls individually, each in its own PR and its own
   approval-gated launch.

## 8. What this does not give you

- **It is not a SCAP scan.** `oscap` with the DISA benchmark is the
  authoritative check. This enforces and evidences; it does not certify.
- **Evidence is ephemeral by default.** Every AAP job runs in a fresh container.
  The report playbook reads evidence off the hosts each time, but the rendered
  POA&M lives in the job's workdir. Archive it to durable storage in a
  downstream node if the assessment package must outlive the job.
- **The inventory source is a placeholder.** A hand-maintained host list is how
  a host quietly stops being scanned.
- **29 of 314 CAT II rules.** See
  [`STIG-CAT-II-Remediation.md`](STIG-CAT-II-Remediation.md#8-adding-the-next-export)
  for adding the rest; the tooling absorbs a new export by dropping a file in.
