# Workflows

**Execution lives in Ansible Automation Platform.** See
[`docs/AAP-INTEGRATION.md`](../../docs/AAP-INTEGRATION.md). GitHub decides what
the baseline *is*; AAP decides what runs, where, and with whose approval.

| Workflow | Trigger | Touches hosts | Status | Purpose |
| --- | --- | --- | --- | --- |
| `stig-validate.yml` | PR, push, manual | No | **Active** | Lint, unit tests, evidence contract, benchmark drift, AAP boundary tests, doc staleness |
| `stig-sync-aap.yml` | Push to main | No | **Active** | Triggers an AAP project sync so the controller runs approved content |
| `stig-remediate.yml` | Manual only | Yes | Superseded | Pre-AAP apply path; kept for sites without AAP |
| `stig-drift.yml` | Manual only | Read-only | Superseded | Pre-AAP drift detection; the nightly audit is an AAP schedule now |

`stig-sync-aap.yml` is deliberately the least privileged thing that could work:
it triggers a project update. It cannot launch a job, reach a managed host, or
approve anything.

Do **not** enable the superseded workflows alongside AAP. Two schedulers
converging the same fleet with different credentials and no shared approval
record is worse than either one alone.

## Required repository configuration

These workflows assume configuration that lives in repository settings, not in
code. Without it they will fail, or worse, silently do nothing useful.

**Environments** (Settings → Environments)

- `aap-controller` — holds `CONTROLLER_HOST` and `CONTROLLER_OAUTH_TOKEN` for
  the sync workflow. Environment-scoped, not repository-scoped, so a fork PR
  cannot reach the token.
- `stig-rhel8_staging` / `stig-rhel8_prod` — only needed for the superseded
  workflows. Under AAP the approval gate is the workflow approval node, held by
  a team that has no execute role.

**Secrets** (scoped to the environments above, not repository-wide)

- `ANSIBLE_SSH_PRIVATE_KEY` — the automation account's key. Scope it to the
  environment so a pull request from a fork cannot reach it.
- `ANSIBLE_KNOWN_HOSTS` — the fleet's host keys. Supplied rather than disabling
  host key checking; a spoofed host should fail to connect, not be hardened.

**Runner**

A self-hosted runner labelled `self-hosted, linux, ansible-control` with network
reach to the managed hosts and a vault password file at `/etc/ansible/vault-pass`.
GitHub-hosted runners cannot reach an internal fleet, and routing them through a
tunnel to do so is a larger security decision than this baseline should make.

**Branch protection** on the default branch

- Require `stig-validate` to pass.
- Require review from Code Owners (see `.github/CODEOWNERS`).
- Disallow force pushes: the commit history is the change record.

**Labels**

Create `stig-drift`, `security`, and `compliance` — the drift workflow applies
them when it opens an issue.
