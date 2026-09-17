# Disk Utilization with an Automation Orchestrator

An Ansible implementation of the threshold-routing workflow: **check → route → remediate → notify**.

Instead of a pass/fail check that pages a human at 3am, the measured percentage
picks one of four branches. 72% and 97% are both "disk alerts", but they need
completely different responses.

```
                      ┌──────────────────────────────────────────┐
   df on every host → │  disk_check: measure, validate, route     │
                      └────────────────────┬─────────────────────┘
                                           │  disk_route
        ┌──────────────┬───────────────────┼───────────────────┬──────────────┐
        │ < 80%        │ 80-95%            │ >= 95%            │ bad data     │
        ▼              ▼                   ▼                   ▼
      ok.yml       cleanup.yml         expand.yml         fallback.yml
   report only   caches, journal,   cleanup + grow EBS   no remediation,
                 rotated logs       + growpart + FS      diagnose & page
        └──────────────┴───────────────────┼───────────────────┴──────────────┘
                                           ▼
                      ┌──────────────────────────────────────────┐
                      │  disk_notify: run log / webhook / email   │
                      └──────────────────────────────────────────┘
```

## Layout

| Path | Purpose |
| --- | --- |
| `disk_utilization.yml` | The orchestrator play: validate config, check, remediate, notify |
| `simulate.yml` | Walks all four branches without waiting for a disk to fill up |
| `inventory/group_vars/all.yml` | Thresholds and every tunable, in one place |
| `roles/disk_check/` | Measures utilization and sets `disk_route` (the switch) |
| `roles/disk_remediate/` | One tasks file per branch, selected by `disk_route_tasks` |
| `roles/disk_notify/` | Renders the summary and delivers it |

## Requirements

* `ansible-core` 2.15+ on the control node; managed nodes need Python and GNU `coreutils` (RHEL 7+).
* Optional: `ansible-galaxy collection install -r requirements.yml` — only needed for
  EBS expansion (`amazon.aws`, plus `boto3`) and SMTP mail (`community.general`).
  The check → route → cleanup → notify path runs on `ansible-core` alone.
* `sudo` on the managed nodes (cleanup touches `/var/log`, `/var/cache`, the journal).

## Walkthrough

### 1. Rehearse every branch first

```bash
cd ansible
ansible-playbook simulate.yml
```

Four simulated readings run end to end against `localhost`. Nothing is deleted and
no AWS API is called — the roles see `disk_simulated` and report what they *would*
do. The run log lands in `../logs/disk-utilization.log`:

```
route=ok       severity=ok       before=75.0% after=75.0%  actions="No action required - utilization is below 80%"
route=cleanup  severity=warning  before=85.0% after=73.0%  actions="Would clear the apt package cache; Would remove 598 aged files (32.3 MiB) ..."
route=expand   severity=critical before=96.0% after=64.0%  actions="... Would grow the EBS volume behind /dev/nvme0n1 by 50%, then run growpart ..."
route=fallback severity=unknown  before=-1.0% after=-1.0%  actions="No remediation attempted - disk data could not be validated; Utilization value outside 0-100: [150.0]"
```

### 2. Point it at real hosts, read-only

Put your hosts in `inventory/hosts.yml`, then:

```bash
ansible-playbook disk_utilization.yml --check --diff
```

`--check` measures for real (the `df` read is explicitly `check_mode: false`) but
changes nothing, and the notification wording switches from "Removed" to
"Would remove" so a dry run can never be mistaken for a real one.

### 3. Let it remediate

```bash
ansible-playbook disk_utilization.yml                      # whole fleet
ansible-playbook disk_utilization.yml -e target=webservers # one group
ansible-playbook disk_utilization.yml -l db01.example.com  # one host
ansible-playbook disk_utilization.yml --tags check         # measure only, skip remediation
```

### 4. Schedule it

```cron
# /etc/cron.d/disk-utilization — every 15 minutes from the control node
*/15 * * * * ansible cd /opt/automation/ansible && ansible-playbook disk_utilization.yml >> /var/log/disk-orchestrator.log 2>&1
```

In AWX/AAP, make it a job template on the same schedule and expose
`disk_threshold_warning`, `disk_threshold_critical` and `disk_expand_enabled` as a survey.

## The branches

### `ok` — below the warning threshold

Records "no action required" and notifies (or stays quiet when
`disk_notify_on_ok: false`). Saying explicitly that nothing was needed is what
makes the run auditable afterwards.

### `cleanup` — between warning and critical

1. Package manager cache (`dnf`/`yum`/`apt clean`).
2. `journalctl --vacuum-size=200M --vacuum-time=7d`.
3. Rotated logs older than `disk_log_age_days` in `/var/log` — only `*.gz`,
   `*.xz`, `*.old`, `*.[0-9]` patterns, so a live log file is never removed.
4. `/tmp` and `/var/cache` entries past their age limit.
5. Re-measures with `df` so the notification reports the real number, not a guess.

### `expand` — at or above critical

Runs the cleanup pass first (it is cheap and buys time), then:

1. Discovers the EBS volume attached to the instance (`ec2_metadata_facts` + `ec2_vol_info`).
2. Grows it by `disk_expand_percent`, capped at `disk_expand_max_gib`, and refuses
   to shrink or no-op.
3. Waits for the kernel to see the larger device (`lsblk`, retried).
4. `growpart` on the partition, then `xfs_growfs` or `resize2fs` on the filesystem.

Expansion is **opt-in** (`disk_expand_enabled: false` by default) because it
changes cloud state and costs money. Without it the host is reported as critical
with "capacity must be added manually".

### `fallback` — anything else

No mounts matched the filters, `df` failed, a percentage came back outside 0-100,
or a task raised an unexpected error (caught by the play's `rescue`). Nothing is
remediated from data that cannot be trusted; the notification names the reason.

## Why `df` and not `ansible_facts.mounts`

The mount facts expose `block_available` but not `block_free`, so
`block_used` is computed as *total − available* and counts root-reserved blocks
as used. On a filesystem with reserved blocks that reads 88% where `df` says 20%.
Thresholds have to mean the same thing in the playbook and in the terminal, so
`disk_check` parses `df -B1 --output=source,fstype,size,used,avail,pcent,target`.

## Tuning

| Variable | Default | Notes |
| --- | --- | --- |
| `disk_threshold_warning` | `80` | Below this, no action |
| `disk_threshold_critical` | `95` | At or above, add capacity |
| `disk_fstype_allow` | ext3/ext4/xfs/btrfs | Keeps tmpfs and overlay out of the report |
| `disk_min_size_bytes` | 1 GiB | Small filesystems cross thresholds for boring reasons |
| `disk_cleanup_enabled` | `true` | Set false to report without touching anything |
| `disk_expand_enabled` | `false` | Opt in per group or host |
| `disk_notify_channels` | `['log']` | Any of `log`, `webhook`, `mail` |

Overrides belong in `inventory/group_vars/<group>.yml` or `host_vars/<host>.yml` —
`db01` already carries a stricter `disk_threshold_critical: 90` as an example.

Keep the webhook URL out of git:

```bash
ansible-vault create inventory/group_vars/disk_managed/vault.yml
# disk_notify_webhook_url: "https://hooks.slack.com/services/..."
ansible-playbook disk_utilization.yml --ask-vault-pass
```

## Extending the pattern

The switch does not care what it is routing on. Swap the measurement in
`disk_check` and the same four-branch structure covers CPU saturation, memory
pressure, or certificate expiry — `< 30 days` warn, `< 7 days` renew,
`expired` page. The branch table lives in one variable:

```yaml
disk_route_tasks:
  ok: ok.yml
  cleanup: cleanup.yml
  expand: expand.yml
  fallback: fallback.yml
```

Add a route name, add a tasks file, and the dispatcher picks it up.

## Verification performed

* `ansible-lint` — passes the `production` profile.
* `simulate.yml` — all four branches route and notify correctly.
* `--check` against a live host — measured 20.0%, matching `df`, routed to `ok`.
* Real cleanup against a scratch directory — removed 3 aged `*.log` files
  (including one nested), left a fresh log and a non-matching file untouched.
* Induced task failure — caught by `rescue`, reported as `fallback`, play still
  ended `failed=0 rescued=1` with the team notified.
