# fapolicyd × Tanium Client — RCA Runbook (RHEL 8 / 9 / 10)

Incident-commander runbook for RHEL endpoints where `fapolicyd` and the Tanium
Client interact badly: client not reporting, sensors returning `TSE-Error`,
tools failing to install, `Operation not permitted`, D-state tasks, fanotify
deadlocks, self-update failures, or hangs after enforcing was turned on.

**Nothing here should be pasted blind.** Rule numbering, default rule contents,
and `fapolicyd-cli` flag availability differ across RHEL 8.x / 9.x / 10 and
across fapolicyd 1.0 / 1.1 / 1.3. The evidence bundle dumps *your* actual
`fapolicyd-cli --list` and `rules.d/` so you tune against reality, not memory.

---

## Contents

| File | Purpose |
|---|---|
| `collect-fapolicyd-tanium-evidence.sh` | **Read-only** one-shot evidence bundle. Touches nothing. Run this first. |
| `controlled-deny-repro.sh` | Phase 3 smoking-gun capture. **Stops the service** — change control required. |

---

## Phase 0 — Stabilize (do not break the box)

Answer these before touching anything:

1. Is SSH still responsive, or is the box wedged?
2. Is fapolicyd enforcing or permissive? `grep ^permissive /etc/fapolicyd/fapolicyd.conf`
3. Are there D-state (uninterruptible) tasks?
   `ps -eo state,pid,wchan:32,comm | awk '$1 ~ /^D/'`
4. What is the timeline: first failure vs. fapolicyd enable vs. Tanium
   deploy/upgrade? A Tanium self-update or tool push immediately before the
   first failure is the single most diagnostic fact available.

**If the box is deadlocking in fanotify:**

- Do **not** attach `gdb`, `strace`, or `ptrace` to `fapolicyd`. Stopping its
  decision thread means no fanotify permission event on the system is ever
  answered — every process that opens a watched file goes uninterruptible and
  the host wedges hard enough to need a reset.
- Prefer `systemctl stop fapolicyd` (with approval) to release pending
  permission events. Reproduce for forensics with `controlled-deny-repro.sh`,
  which runs a foreground daemon in permissive mode.
- If it is already too wedged to stop the service, boot with
  `systemd.mask=fapolicyd.service` from the GRUB line and collect offline.

---

## Phase 1 — Identity, versions, footprint

Collected into `01-identity.txt` and `02-tanium-tree.txt`.

| Command | What you are looking for |
|---|---|
| `cat /etc/redhat-release; uname -r` | Kernel age. fanotify permission-event fixes matter; pre-8.6 kernels are a known deadlock risk. |
| `rpm -q fapolicyd; rpm -qa \| grep -i tanium` | fapolicyd version gates which CLI flags exist. `TaniumClient` present in rpmdb ⇒ RPM-installed ⇒ rpmdb trust backend may already cover the *original* files. |
| `systemctl status fapolicyd taniumclient` | Restart loops, OOM kills, start-time correlation. |
| `getenforce; sestatus` | Rules out / rules in root-cause class G. |
| `mount \| grep -E 'noexec\|nfs\|tmpfs'` | `noexec` on a mount holding Tanium content produces `EACCES` that looks exactly like a fapolicyd deny but is not. NFS in the decision path is the classic deadlock. |
| `find /opt/Tanium -type f -perm /111` | The real allowlisting surface. Typically **thousands** of files. |
| `rpm -V TaniumClient` | `S.5....T` on client binaries proves the tree drifted from the RPM — i.e. a self-update ran. This is the highest-probability finding in practice. |
| fanotify fd scan (in the bundle) | More than one fanotify consumer ⇒ EDR/AV contention, serialized decisions, latency, possible deadlock. |

**Key Tanium paths that must be in scope** (confirm against the actual tree —
layout varies by client version and by which modules are deployed):

```
/opt/Tanium/TaniumClient/                     core binaries, libs
/opt/Tanium/TaniumClient/Tools/               module tools (Patch, Comply, Threat Response, StdUtils, BASH)
/opt/Tanium/TaniumClient/extensions/          Client Extensions (libTaniumCX.so, TaniumCX)
/opt/Tanium/TaniumClient/Downloads/           staged content + self-update payloads
/opt/Tanium/TaniumClient/Backup/              prior-version binaries kept across upgrades
/opt/Tanium/TaniumClient/Logs/                (data only, no trust needed)
```

Treat the fapolicyd allowlist as the **same object** as your documented Tanium
AV/EDR exclusions. Tanium publishes exclusion paths for AV products; fapolicyd
is an allowlisting control over the identical trees and needs the identical
path list, plus `Downloads/` and `Backup/`, which AV exclusion lists sometimes
omit.

---

## Phase 2 — fapolicyd health

Collected into `03-fapolicyd-health.txt` … `07-ftype.txt`.

### Configuration knobs that actually cause this incident

```bash
grep -vE '^\s*(#|$)' /etc/fapolicyd/fapolicyd.conf
```

| Setting | Why it bites Tanium |
|---|---|
| `permissive` | `0` in production with no prior `deny_audit` soak is the operational root cause behind most of these tickets. |
| `integrity` | `none` / `size` / `ima` / `sha256`. With `sha256`, **any** Tanium self-update invalidates every trusted hash in the tree at once. This is the difference between "worked for six weeks then died overnight" and "never worked". |
| `trust` | `rpmdb,file`. If `file` is absent, `fapolicyd-cli --file add` writes a trust file that is never read. |
| `db_max_size` | Default 50 (MiB). The Tanium tree is large; adding it plus a big rpmdb can exhaust the LMDB map and produce `MDB_MAP_FULL` / partial trust — denials that look random. Raise before adding the tree. |
| `watch_fs` | Default includes `tmpfs`. Adding `nfs`/`nfs4` puts network I/O inside the decision path — the canonical deadlock. |
| `q_size` | Default 800. Overflow under a Tanium scan/patch burst drops decisions; the daemon logs queue-full and behavior degrades to intermittent denies. |
| `subj_cache_size` / `obj_cache_size` | Undersized caches under Tanium's churn cause thrash and latency, which reads as "the client is slow / times out". |
| `allow_filesystem_mark` | Interacts with container and overlay workloads. |

### Rules: on-disk vs. compiled vs. loaded

These are three different things and they disagree more often than you would like.

```bash
fagenrules --check              # do the compiled rules match rules.d/ ?
ls -l /etc/fapolicyd/rules.d/   # source, evaluated in numeric filename order
cat /etc/fapolicyd/compiled.rules
fapolicyd-cli --list            # <-- LIVE, numbered. THIS is what decides.
```

**`fapolicyd-cli --list` is the only authoritative view.** The numbers it
prints are the rule numbers that appear in denial records — that is how you map
a denial to the rule that caused it.

Two failure modes here:

- **Old + new rules coexist.** A legacy monolithic `/etc/fapolicyd/fapolicyd.rules`
  alongside `rules.d/` is unsupported; behavior depends on version and you can
  end up enforcing rules you cannot see in `rules.d/`. The bundle checks for
  this explicitly (`04-fapolicyd-config.txt`).
- **Wrong numeric order.** First match wins. A perfectly correct Tanium allow
  in `80-tanium.rules` is dead code if an earlier default rule already denied
  the same access.

### The ordering trap that catches almost everyone

The stock RHEL ruleset contains, roughly in this order:

```
10-languages.rules      deny/handle interpreted content by ftype (%languages macro)
...
41-shared-obj.rules     open of shared objects
42-trusted-elf.rules
70-trusted-lang.rules
72-shell.rules
73-known-libs.rules
90-deny-execute.rules   deny_audit perm=execute all : all      <-- the catch-all
95-allow-open.rules     allow    perm=open    all : all
```

Everyone numbers their Tanium rules `80-…` because they are thinking about
`90-deny-execute`. That is correct **only for the execute catch-all**. If your
denial comes from the `%languages` handling at `10-…` (Tanium's TPython, shell
sensors, `.py` content), an `80-` rule never runs — evaluation already
stopped. Read `fapolicyd-cli --list`, find the rule number in the denial, and
number your file *below that rule*.

### What does fapolicyd think the file *is*?

```bash
fapolicyd-cli --ftype /opt/Tanium/TaniumClient/Tools/…/somefile
```

fapolicyd classifies with libmagic, not by extension. A Tanium sensor with no
extension may come back `text/x-python` or `text/x-shellscript` and land in the
`%languages` set; a CX plugin may come back `application/x-sharedlib` and be
governed by *open* rules, not *execute* rules. Guessing the ftype is how people
write rules that never match. The bundle runs this across the tree
(`07-ftype.txt`).

---

## Phase 3 — Prove the deny

Passive first (`08-denials-audit.txt`, `09-denials-journal.txt`):

```bash
ausearch -m FANOTIFY -ts recent -i          # resp=2 == DENY, resp=1 == allow
ausearch -m FANOTIFY -ts recent -i | grep -iB12 tanium
journalctl -u fapolicyd -u taniumclient --since '2 hours ago' --no-pager
dmesg -T | grep -iE 'blocked for more than|hung_task|fanotify'
```

A `FANOTIFY` event is a group of records. The `FANOTIFY` record carries
`resp=2`; the accompanying `SYSCALL` / `PATH` / `PROCTITLE` records carry the
subject (`exe=`, `comm=`, `auid=`, `pid=`) and the object (`name=`). Read them
together — the `FANOTIFY` line alone tells you nothing about *what* was denied.

fapolicyd's own syslog line is the richer artifact when
`syslog_format` / `detailed_report` is configured:

```
rule=13 dec=deny_audit perm=execute auid=0 pid=2264 exe=/opt/Tanium/TaniumClient/TaniumClient : path=/opt/Tanium/TaniumClient/Tools/Comply/scanner ftype=application/x-executable trust=0
```

Every field matters:

- `rule=13` → index into `fapolicyd-cli --list`. Tells you *which* rule to get in front of.
- `perm=execute` vs `perm=open` → an `execute` allow does nothing for a `.so` being `dlopen`ed.
- `exe=` → the **subject**. Often the Tanium client itself launching a helper.
- `path=` / `ftype=` → the **object** and its libmagic type.
- `trust=0` → not in the trust DB at all. `trust=1` with a deny means the rule denied a *trusted* file — a rules problem, not a trust problem. This one field splits root-cause class A from class C/F.

### Active capture (change control required)

`controlled-deny-repro.sh` stops the service and runs:

```bash
fapolicyd --permissive --debug-deny 2>/tmp/fapo-deny.log
```

Permissive means the reproduction **cannot** be blocked, while `--debug-deny`
prints every would-be denial. Two outcomes, both decisive:

- Denials appear naming Tanium paths → fapolicyd is the cause; you now have the
  exact rule/perm/exe/path/ftype/trust tuple to fix.
- **Tanium still fails with nothing blocked** → fapolicyd is innocent. Go to
  SELinux, `noexec`, EDR, or the client itself (root-cause class G).

Do the control test in this order: reproduce with fapolicyd stopped (works?),
then with permissive+debug-deny (what would have been denied?), then fix.

---

## Phase 4 — Tanium-side evidence

- `/opt/Tanium/TaniumClient/Logs/` — grep for `Operation not permitted`,
  `Permission denied`, `EPERM`, `failed to exec`, `cannot execute`.
- Client Extension logs; whether shared-process CX mode is enabled (one
  `TaniumCX` process hosting extensions changes which `exe=` appears as the
  subject in denials — rules written against per-tool binaries stop matching).
- Console: registration state, last-seen time, the literal `TSE-Error` text.
  `TSE-Error` is a sensor-execution error — it usually names the script or
  interpreter that failed, which maps directly onto a `%languages` denial.
- Endpoint Configuration: tool/CX install errors, "needs attention" state.
- `rpm -V TaniumClient` + compare on-disk sha256 (`11-hash-reality.txt`)
  against the trust DB dump (`06-trustdb.txt`).

---

## Phase 5 — Correlate

Build this table from the bundle. One row per distinct denial.

| Denied path | `exe=` (subject) | `ftype=` | In trust DB? | rpm-owned? | Hash matches? | Rule # | Tanium component |
|---|---|---|---|---|---|---|---|
| | | | | | | | |

Then name the class:

| Class | Root cause | Decisive evidence |
|---|---|---|
| **A** | Missing trust for the `/opt/Tanium` tree | `trust=0`, path absent from `--dump-db`, denial at the catch-all rule |
| **B** | Stale/mismatched hashes after a Tanium self-update | `--check-trustdb` miscompares on Tanium paths; `rpm -V` shows `5` (sha256 differs); failure starts right after an upgrade |
| **C** | Interpreter / script / `%languages` rule | Denial rule number is in the 10-range; `ftype=text/x-python` or `text/x-shellscript`; TPython or sensor scripts |
| **D** | Shared-object `open` denied, not `execute` | `perm=open`, `ftype=application/x-sharedlib`, CX `.so` files |
| **E** | fanotify deadlock / `watch_fs` / NFS | D-state tasks, `blocked for more than 120 seconds`, `fanotify` in stacks, NFS in `watch_fs` or in the decision path |
| **F** | Broken rules compilation / old+new rules | `fagenrules --check` disagrees; legacy `fapolicyd.rules` coexists with `rules.d/`; `--list` does not contain your rule |
| **G** | SELinux / third-party agent — fapolicyd is innocent | Still fails in permissive+debug-deny with no Tanium denials; AVCs present; multiple fanotify consumers |
| **H** | Performance / queue overflow masquerading as random denials | Intermittent and load-correlated; `--check-status` shows queue depth and cache-miss pressure; `db_max_size` exhausted |

---

## Remediation, in layers

### Layer 1 — Immediate restore (temporary, ticketed, with an expiry)

```bash
# permissive keeps the daemon logging what it WOULD deny - strongly preferred
# over stopping it, because the soak data is exactly what you need next.
sed -i 's/^permissive.*/permissive = 1/' /etc/fapolicyd/fapolicyd.conf
systemctl restart fapolicyd
systemctl restart taniumclient
```

Never leave production with fapolicyd off or permissive without a ticket and a
dated expiry. Note the compliance exposure explicitly — many baselines require
the deny-by-default posture.

### Layer 2 — Correct trust (preferred over broad allow rules)

Trust is hash+size based, survives audit, and is the STIG-friendly answer.
Allow rules are blunt and permanent.

**RPM-installed client, not yet self-updated:**

```bash
rpm -V TaniumClient                       # confirm no drift
fapolicyd-cli --update                    # rebuild from rpmdb backend
```

**The living, self-updating tree (the normal case):**

```bash
# confirm the file backend is enabled first, or this writes a file nobody reads
grep -E '^trust' /etc/fapolicyd/fapolicyd.conf     # expect: trust = rpmdb,file

# raise the LMDB map BEFORE adding a large tree
grep -E '^db_max_size' /etc/fapolicyd/fapolicyd.conf

# add the tree into a dedicated, named trust file you can manage/diff/revert
fapolicyd-cli --file add /opt/Tanium --trust-file tanium
fapolicyd-cli --update

# verify
fapolicyd-cli --check-trustdb | grep -i tanium      # want: clean
fapolicyd-cli --dump-db | grep -ci tanium           # want: non-zero, plausible
```

`--trust-file tanium` writes `/etc/fapolicyd/trust.d/tanium` instead of dumping
into the shared `fapolicyd.trust`. Do this — it is the difference between a
reviewable, revertible allowlist object and an unmanageable blob.

**Ordering matters with `integrity = sha256`:** add trust only *after* Tanium
has finished writing. Trusting a tree mid-upgrade records hashes of files that
are about to be replaced, and you get a clean `--update` followed by denials an
hour later.

### Layer 3 — Precise rules (only for what trust cannot cover)

Trust cannot cover content whose hash legitimately changes between the trust
update and execution — downloaded scanner payloads, generated scripts, staged
tool content. That is where rules earn their place.

Pick the number *after* reading `fapolicyd-cli --list`, not from this document.
`/etc/fapolicyd/rules.d/80-tanium.rules`:

```
# Subject: the Tanium client itself, acting on its own tree.
allow perm=any exe=/opt/Tanium/TaniumClient/TaniumClient : dir=/opt/Tanium/

# Client Extensions host process (only if shared-process CX mode is in use).
allow perm=any exe=/opt/Tanium/TaniumClient/extensions/TaniumCX : dir=/opt/Tanium/

# Shared objects the client dlopen()s - note perm=open, NOT execute.
allow perm=open all : dir=/opt/Tanium/
```

Then:

```bash
chown root:fapolicyd /etc/fapolicyd/rules.d/80-tanium.rules
chmod 644 /etc/fapolicyd/rules.d/80-tanium.rules
fagenrules --check
fagenrules --load           # compile + reload; restart fapolicyd if unsure
fapolicyd-cli --list | sed -n '1,120p'      # CONFIRM your rule is loaded and where
```

**Syntax warnings — these are real bugs I see in copy-pasted snippets:**

- **One value per attribute.** `exe=/usr/bin/python3 /usr/bin/bash /usr/bin/sh`
  is **invalid**. fapolicyd does not accept value lists. Write one rule per
  interpreter, or use a subject attribute that genuinely covers the set.
- **`dir=` needs the trailing slash**, and matches by prefix. `dir=/opt/Tanium/`
  covers the whole tree — including `Downloads/`, where untrusted content lands.
  That is the trade-off you are making; make it knowingly.
- **`trust=1` in the object is a trap here.** `allow perm=any all : dir=/opt/Tanium/ trust=1`
  requires the file to be in the trust DB — which is exactly what fails after a
  self-update. It reads like defense in depth and behaves like the bug you are
  trying to fix.
- **Never write `allow perm=any all : all`.** That is not a Tanium exception,
  it is turning the control off while leaving the service running — the worst
  of both worlds, because you keep the compliance claim and lose the control.
- Prefer constraining the **subject** (`exe=`) over blanket object allows. An
  attacker who can drop a file into `/opt/Tanium/Downloads/` gets execution
  from `allow perm=any all : dir=/opt/Tanium/`, but not from a rule that also
  requires the Tanium client to be the one executing it.

### Layer 4 — Deadlock / hang specific (class E)

- Confirm the kernel carries current fanotify permission-event fixes: RHEL 8.6+,
  9.x, or 10. Older 8.x is a known hazard under EDR + fapolicyd together.
- Remove `nfs` / `nfs4` from `watch_fs`. Never let a decision require network
  I/O; an NFS stall becomes a system-wide hang because every waiter blocks
  behind the unanswered permission event.
- Keep `tmpfs` in `watch_fs` unless it is provably the overload source —
  removing it creates a real execution blind spot.
- Audit for other fanotify permission-event consumers (the bundle lists
  processes holding fanotify fds). Two agents answering permission events on
  the same opens serialize latency and can deadlock each other. Decide which
  one owns execution control.
- Containers present: apply the documented `ld_so` pattern allowance for
  runc/podman, and verify against your fapolicyd version's pattern support.
- Ensure `/opt/Tanium` is not on a filesystem fapolicyd itself must traverse to
  make a decision about fapolicyd's own dependencies.

### Layer 5 — Make it operable (this is the actual fix)

The technical fix is Layer 2. The *root* cause is almost always that no process
exists to re-trust the tree after Tanium changes it. Tanium updates itself;
fapolicyd trust is a point-in-time snapshot. Those two facts guarantee recurrence
unless you automate.

- **Pipeline step after every Tanium Client / CX / tool deployment:**
  `fapolicyd-cli --file update /opt/Tanium --trust-file tanium && fapolicyd-cli --update && fapolicyd-cli --check-trustdb | grep -i tanium`
- Manage the `tanium` trust file with Ansible or the RHEL `fapolicyd` system
  role so it is declarative and diffable, not hand-edited.
- **Soak in `permissive = 1` with `deny_audit` for 7 days**, review
  `ausearch -m FANOTIFY`, *then* enforce. Enforcing without a soak is how this
  incident happened.
- Document the Tanium path list as a standard exception object filed next to
  the AV/EDR exclusions, owned by the same team, reviewed on the same cadence.
- Monitor: fapolicyd denials mentioning `/opt/Tanium`, `hung_task` in dmesg,
  and Tanium client last-seen age. Alert on the first, page on the last two.

---

## Validation checklist

```bash
systemctl is-active fapolicyd taniumclient
fapolicyd-cli --check-trustdb | grep -i tanium          # clean
ausearch -m FANOTIFY -ts recent | grep -i tanium        # no unexpected denies
ausearch -m avc -ts recent | grep -i tanium             # no AVCs
```

- Client registers and answers a simple Interact question.
- Deploy a no-op action and one tool install — tool install is the real test,
  because it writes new files.
- **Reboot test.** Re-verify trust and client health after a reboot; hash/trust
  drift that only appears post-reboot is a known class of problem.
- Re-run the validation after the *next* client self-update. That is the event
  the fix actually has to survive.

---

## What NOT to do

| Don't | Why |
|---|---|
| `gdb`/`strace`/`ptrace` on `fapolicyd` | SIGSTOPs the decision thread; every fanotify permission event on the host blocks; needs a hard reset. |
| `rm -rf /var/lib/fapolicyd/*.mdb` casually | Only with the service stopped, and only when you intend a full `--update` rebuild. Otherwise you get partial trust and denials that look random. |
| `setenforce 0` "to test" | Changes two variables at once and destroys the SELinux evidence you need to rule class G in or out. Read the AVCs instead. |
| `allow perm=any all : all` | Keeps the compliance claim, removes the control. |
| Leave fapolicyd stopped "until we figure it out" | Undocumented control gap with no expiry. Use `permissive = 1` — it keeps producing the soak data you need. |
| Trust the tree mid-upgrade under `integrity = sha256` | Records hashes of files about to be replaced; clean now, broken in an hour. |
| Copy rule numbers from a runbook | Including this one. Read `fapolicyd-cli --list` on the actual host. |
