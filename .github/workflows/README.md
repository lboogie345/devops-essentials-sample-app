# Workflows

| Workflow | Trigger | Touches hosts | Purpose |
| --- | --- | --- | --- |
| `stig-validate.yml` | PR, push, manual | No | Lint, unit tests, evidence-schema contract, benchmark drift |
| `stig-remediate.yml` | Manual only | Yes | Applies the baseline to a named tier, behind environment approval |
| `stig-drift.yml` | Nightly, manual | Read-only | Continuous monitoring; opens/updates one drift issue |

## Required repository configuration

These workflows assume configuration that lives in repository settings, not in
code. Without it they will fail, or worse, silently do nothing useful.

**Environments** (Settings → Environments)

- `stig-rhel8_staging` — no required reviewers; this tier absorbs mistakes.
- `stig-rhel8_prod` — required reviewers set to the security engineering team,
  plus a wait timer if your change window demands one. This is the approval gate
  that satisfies CM-3; the workflow cannot start applying to production until a
  human approves the run.

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
