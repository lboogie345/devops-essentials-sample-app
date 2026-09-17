#!/usr/bin/env bash
#
# collect-fapolicyd-tanium-evidence.sh
#
# READ-ONLY evidence collector for fapolicyd <-> Tanium Client incidents on
# RHEL 8 / 9 / 10 (and Alma / Rocky / Oracle clones).
#
# WHAT IT DOES NOT DO (by design):
#   - does not start, stop, restart, or reload any service
#   - does not modify the trust database, rules, or fapolicyd.conf
#   - does not ptrace / gdb / strace fapolicyd (that SIGSTOPs the decision
#     thread and deadlocks every fanotify permission event on the box)
#   - does not delete /var/lib/fapolicyd/*.mdb
#
# Output: /var/tmp/fapo-tanium-<hostname>-<UTC timestamp>/ plus a .tar.gz
#
# Usage:
#   sudo bash collect-fapolicyd-tanium-evidence.sh
#   sudo TANIUM_DIR=/opt/Tanium bash collect-fapolicyd-tanium-evidence.sh
#   sudo SINCE='4 hours ago' bash collect-fapolicyd-tanium-evidence.sh
#
set -u

TANIUM_DIR="${TANIUM_DIR:-/opt/Tanium}"
SINCE="${SINCE:-24 hours ago}"
AUSEARCH_TS="${AUSEARCH_TS:-recent}"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="/var/tmp/fapo-tanium-$(hostname -s)-${TS}"
mkdir -p "$OUT" || { echo "cannot create $OUT"; exit 1; }
chmod 700 "$OUT"

log() { printf '%s\n' "$*" >&2; }

# run <outfile> <command...>  -- records the command, stdout, stderr, rc
run() {
  local f="$OUT/$1"; shift
  {
    printf '### CMD: %s\n' "$*"
    printf '### DATE: %s\n\n' "$(date -u +%FT%TZ)"
  } >>"$f"
  if ! command -v "${1}" >/dev/null 2>&1 && [ "${1}" != "bash" ] && [ "${1}" != "sh" ]; then
    printf '!!! NOT INSTALLED: %s\n\n' "$1" >>"$f"
    return 0
  fi
  timeout 60 "$@" >>"$f" 2>&1
  printf '\n### RC: %s\n\n' "$?" >>"$f"
}

# shell_run <outfile> <shell string> -- for pipelines
shell_run() {
  local f="$OUT/$1"; shift
  {
    printf '### SH: %s\n' "$*"
    printf '### DATE: %s\n\n' "$(date -u +%FT%TZ)"
  } >>"$f"
  timeout 60 bash -c "$*" >>"$f" 2>&1
  printf '\n### RC: %s\n\n' "$?" >>"$f"
}

log "==> collecting into $OUT"

##############################################################################
# PHASE 0 - stabilize / is the box actually wedged
##############################################################################
log "--> phase 0: stability"
run 00-stability.txt uptime
shell_run 00-stability.txt "cat /proc/loadavg"
# D-state (uninterruptible) tasks: the fanotify-deadlock fingerprint
shell_run 00-stability.txt "ps -eo state,pid,ppid,wchan:32,comm,args --sort=state | awk 'NR==1 || \$1 ~ /^D/'"
shell_run 00-stability.txt "for p in \$(ps -eo state=,pid= | awk '\$1 ~ /^D/ {print \$2}'); do echo \"--- pid \$p (\$(cat /proc/\$p/comm 2>/dev/null))\"; cat /proc/\$p/stack 2>/dev/null | head -25; done"
shell_run 00-stability.txt "dmesg -T 2>/dev/null | grep -iE 'blocked for more than|hung_task|fanotify|fsnotify|Tanium|fapolicyd|oom-kill|Out of memory' | tail -200"
run 00-stability.txt sysctl kernel.hung_task_timeout_secs kernel.hung_task_panic

##############################################################################
# PHASE 1 - identity, versions, footprint
##############################################################################
log "--> phase 1: identity & versions"
shell_run 01-identity.txt "cat /etc/redhat-release 2>/dev/null; cat /etc/os-release"
run 01-identity.txt uname -a
shell_run 01-identity.txt "rpm -q fapolicyd audit libmagic file selinux-policy-targeted kernel 2>&1"
shell_run 01-identity.txt "rpm -qa | grep -iE 'tanium' 2>&1"
shell_run 01-identity.txt "rpm -qi fapolicyd 2>&1 | sed -n '1,25p'"
shell_run 01-identity.txt "rpm -q --changelog fapolicyd 2>/dev/null | head -60"
run 01-identity.txt systemctl status fapolicyd --no-pager -l
run 01-identity.txt systemctl status taniumclient --no-pager -l
shell_run 01-identity.txt "systemctl is-active fapolicyd taniumclient auditd; systemctl is-enabled fapolicyd taniumclient auditd"
shell_run 01-identity.txt "getenforce; sestatus 2>&1; semodule -l 2>/dev/null | grep -iE 'tanium|fapolicyd'"
shell_run 01-identity.txt "mount | grep -iE 'noexec|nosuid|nfs|tmpfs|fuse|overlay'"
shell_run 01-identity.txt "findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS -t nfs,nfs4,tmpfs,overlay,fuse.sshfs 2>/dev/null"
shell_run 01-identity.txt "df -hT | sed -n '1,40p'"
shell_run 01-identity.txt "ps -efZ 2>/dev/null | grep -iE 'fapolicyd|[T]anium|taniumcx|TaniumCX' | grep -v grep"

# Other fanotify / EDR consumers - contention is a real root-cause class
shell_run 01-identity.txt "echo '--- processes holding fanotify fds ---'; for p in /proc/[0-9]*; do pid=\${p#/proc/}; if ls -l \$p/fd 2>/dev/null | grep -q 'anon_inode:\\[fanotify\\]'; then echo \"pid \$pid \$(cat \$p/comm 2>/dev/null) : \$(ls -l \$p/fd 2>/dev/null | grep -c 'anon_inode:\\[fanotify\\]') fanotify fd(s)\"; fi; done"
shell_run 01-identity.txt "rpm -qa 2>/dev/null | grep -iE 'crowdstrike|falcon|carbonblack|cb-|sentinel|cortex|traps|mcafee|trellix|ds_agent|tenable|nessus|qualys|rapid7|insight|clamav|eset|sophos|trendmicro|osquery|wazuh|velociraptor'"
shell_run 01-identity.txt "lsmod 2>/dev/null | grep -iE 'falcon|cb_|sensor|tanium|redcanary'"

##############################################################################
# PHASE 1b - Tanium tree footprint
##############################################################################
log "--> phase 1b: Tanium tree"
shell_run 02-tanium-tree.txt "ls -ldZ ${TANIUM_DIR} ${TANIUM_DIR}/TaniumClient 2>&1"
shell_run 02-tanium-tree.txt "find ${TANIUM_DIR} -maxdepth 2 -type d 2>/dev/null | sort"
shell_run 02-tanium-tree.txt "echo '--- executable/regular file count ---'; find ${TANIUM_DIR} -xdev -type f 2>/dev/null | wc -l; echo '--- mode +x count ---'; find ${TANIUM_DIR} -xdev -type f -perm /111 2>/dev/null | wc -l; echo '--- tree size ---'; du -sh ${TANIUM_DIR} 2>/dev/null"
shell_run 02-tanium-tree.txt "find ${TANIUM_DIR} -xdev -type f -perm /111 2>/dev/null | head -400"
shell_run 02-tanium-tree.txt "echo '--- shared objects ---'; find ${TANIUM_DIR} -xdev -type f -name '*.so*' 2>/dev/null | head -200"
shell_run 02-tanium-tree.txt "echo '--- interpreted content (py/sh/vbs/js) ---'; find ${TANIUM_DIR} -xdev -type f \\( -name '*.py' -o -name '*.pyc' -o -name '*.sh' -o -name '*.js' -o -name '*.pl' \\) 2>/dev/null | head -200"
# Files written recently == self-update / tool deploy == hash drift window
shell_run 02-tanium-tree.txt "echo '--- files modified in last 14 days (drift window) ---'; find ${TANIUM_DIR} -xdev -type f -mtime -14 -printf '%TY-%Tm-%Td %TH:%TM  %s  %p\\n' 2>/dev/null | sort | tail -200"
shell_run 02-tanium-tree.txt "echo '--- SELinux labels, top level ---'; ls -lZ ${TANIUM_DIR}/TaniumClient 2>/dev/null | head -60"
# Was it RPM installed, and has it drifted from the RPM?
shell_run 02-tanium-tree.txt "echo '--- rpm -V TaniumClient (S=size 5=sha256 T=mtime differ) ---'; rpm -V TaniumClient 2>&1 | head -200"
shell_run 02-tanium-tree.txt "echo '--- which Tanium files are rpm-owned at all ---'; for f in \$(find ${TANIUM_DIR} -xdev -type f -perm /111 2>/dev/null | head -60); do printf '%s\\t%s\\n' \"\$(rpm -qf \"\$f\" 2>&1 | tr -d '\\n')\" \"\$f\"; done"

##############################################################################
# PHASE 2 - fapolicyd health
##############################################################################
log "--> phase 2: fapolicyd health"
run 03-fapolicyd-health.txt fapolicyd-cli --check-config
run 03-fapolicyd-health.txt fapolicyd-cli --check-watch_fs
run 03-fapolicyd-health.txt fapolicyd-cli --check-path
# --check-status asks the running daemon for its internal state report
# (object/subject cache hit rates, queue depth). Needs the daemon running.
run 03-fapolicyd-health.txt fapolicyd-cli --check-status
shell_run 03-fapolicyd-health.txt "cat /run/fapolicyd/fapolicyd.state 2>/dev/null | head -120"

shell_run 04-fapolicyd-config.txt "grep -vE '^\\s*(#|\$)' /etc/fapolicyd/fapolicyd.conf"
shell_run 04-fapolicyd-config.txt "echo '=== FULL CONF (with comments) ==='; cat /etc/fapolicyd/fapolicyd.conf"
shell_run 04-fapolicyd-config.txt "echo '=== unit overrides ==='; systemctl cat fapolicyd --no-pager"
shell_run 04-fapolicyd-config.txt "echo '=== trust backends / dirs ==='; ls -l /etc/fapolicyd/ /etc/fapolicyd/rules.d/ /etc/fapolicyd/trust.d/ 2>&1"
shell_run 04-fapolicyd-config.txt "echo '=== legacy monolithic rules file present? (old+new conflict) ==='; ls -l /etc/fapolicyd/fapolicyd.rules 2>&1; ls -l /etc/fapolicyd/compiled.rules 2>&1"
shell_run 04-fapolicyd-config.txt "echo '=== trustdb on disk ==='; ls -l /var/lib/fapolicyd/ 2>&1; du -sh /var/lib/fapolicyd/ 2>/dev/null"

# Rules: what is on disk vs what the daemon actually compiled and loaded
shell_run 05-rules.txt "echo '=== fagenrules --check ==='; fagenrules --check 2>&1"
shell_run 05-rules.txt "echo '=== rules.d contents, in evaluation order ==='; for f in /etc/fapolicyd/rules.d/*.rules; do echo \"----- \$f -----\"; cat \"\$f\"; echo; done 2>&1"
shell_run 05-rules.txt "echo '=== legacy /etc/fapolicyd/fapolicyd.rules (should NOT coexist with rules.d) ==='; cat /etc/fapolicyd/fapolicyd.rules 2>&1"
shell_run 05-rules.txt "echo '=== compiled.rules as the daemon sees it ==='; cat /etc/fapolicyd/compiled.rules 2>&1"
shell_run 05-rules.txt "echo '=== fapolicyd-cli --list (LIVE loaded rules, numbered - this is what matters) ==='; fapolicyd-cli --list 2>&1"

# Trust database
log "--> phase 2b: trust database (this can take a minute)"
shell_run 06-trustdb.txt "echo '=== trust entries mentioning Tanium ==='; fapolicyd-cli --dump-db 2>/dev/null | grep -i tanium | head -400"
shell_run 06-trustdb.txt "echo '=== trust entry counts ==='; fapolicyd-cli --dump-db 2>/dev/null | wc -l; echo 'tanium entries:'; fapolicyd-cli --dump-db 2>/dev/null | grep -ci tanium"
shell_run 06-trustdb.txt "echo '=== --check-trustdb: FULL (miscompares = stale hash/size) ==='; fapolicyd-cli --check-trustdb 2>&1 | head -400"
shell_run 06-trustdb.txt "echo '=== --check-trustdb filtered on Tanium/miscompare/error ==='; fapolicyd-cli --check-trustdb 2>&1 | grep -iE 'tanium|miscompare|mismatch|error|missing|no longer' | head -200"
shell_run 06-trustdb.txt "echo '=== file trust source files ==='; for f in /etc/fapolicyd/trust.d/* /etc/fapolicyd/fapolicyd.trust; do [ -f \"\$f\" ] && { echo \"----- \$f -----\"; head -100 \"\$f\"; echo; }; done 2>&1"

# What does fapolicyd think these files ARE? (ftype drives %languages rules)
shell_run 07-ftype.txt "echo '=== fapolicyd-cli --ftype on key Tanium objects ==='; for f in \$(find ${TANIUM_DIR} -xdev -type f \\( -perm /111 -o -name '*.so*' -o -name '*.py' \\) 2>/dev/null | head -80); do printf '%s\\t%s\\n' \"\$(fapolicyd-cli --ftype \"\$f\" 2>&1 | tr -d '\\n')\" \"\$f\"; done"

##############################################################################
# PHASE 3 - prove the deny
##############################################################################
log "--> phase 3: denials"
shell_run 08-denials-audit.txt "echo '=== aureport summary ==='; aureport --summary -i --start ${AUSEARCH_TS} 2>&1 | head -60"
shell_run 08-denials-audit.txt "echo '=== FANOTIFY records (resp=2 means DENY) ==='; ausearch -m FANOTIFY -ts ${AUSEARCH_TS} -i 2>&1 | tail -500"
shell_run 08-denials-audit.txt "echo '=== FANOTIFY records mentioning Tanium ==='; ausearch -m FANOTIFY -ts ${AUSEARCH_TS} -i 2>&1 | grep -iB12 tanium | tail -400"
shell_run 08-denials-audit.txt "echo '=== SELinux AVCs (rules out / rules in compounding control) ==='; ausearch -m avc,user_avc,selinux_err -ts ${AUSEARCH_TS} -i 2>&1 | tail -300"
shell_run 08-denials-audit.txt "echo '=== AVCs mentioning Tanium ==='; ausearch -m avc -ts ${AUSEARCH_TS} -i 2>&1 | grep -i tanium | tail -100"

shell_run 09-denials-journal.txt "echo '=== fapolicyd journal ==='; journalctl -u fapolicyd --since '${SINCE}' --no-pager 2>&1 | tail -600"
shell_run 09-denials-journal.txt "echo '=== taniumclient journal ==='; journalctl -u taniumclient --since '${SINCE}' --no-pager 2>&1 | tail -400"
shell_run 09-denials-journal.txt "echo '=== any dec=deny / rule= lines anywhere in the journal ==='; journalctl --since '${SINCE}' --no-pager 2>&1 | grep -iE 'dec=deny|deny_audit|fapolicyd.*rule=' | tail -400"
shell_run 09-denials-journal.txt "echo '=== journal lines mentioning Tanium ==='; journalctl --since '${SINCE}' --no-pager 2>&1 | grep -i tanium | tail -300"
shell_run 09-denials-journal.txt "echo '=== kernel ring buffer ==='; journalctl -k --since '${SINCE}' --no-pager 2>&1 | grep -iE 'blocked for more than|hung_task|fanotify|call trace' | tail -200"

##############################################################################
# PHASE 4 - Tanium-side evidence
##############################################################################
log "--> phase 4: Tanium logs"
mkdir -p "$OUT/tanium-logs"
shell_run 10-tanium-client.txt "ls -lR ${TANIUM_DIR}/TaniumClient/Logs 2>&1 | head -80"
# Copy the tail of each client log rather than the whole thing (they are large)
shell_run 10-tanium-client.txt "for f in ${TANIUM_DIR}/TaniumClient/Logs/*.txt ${TANIUM_DIR}/TaniumClient/Logs/*.log; do [ -f \"\$f\" ] || continue; b=\$(basename \"\$f\"); tail -c 2000000 \"\$f\" > '${OUT}'/tanium-logs/\"\$b\" 2>/dev/null; echo \"copied tail of \$f\"; done"
shell_run 10-tanium-client.txt "echo '=== client log lines that look like permission failures ==='; grep -rhiE 'operation not permitted|permission denied|EPERM|EACCES|failed to (exec|launch|load|start)|cannot execute|error 1\\b' ${TANIUM_DIR}/TaniumClient/Logs 2>/dev/null | tail -200"
shell_run 10-tanium-client.txt "echo '=== Client Extensions / Endpoint Configuration ==='; ls -lR ${TANIUM_DIR}/TaniumClient/extensions 2>/dev/null | head -100; ls -l ${TANIUM_DIR}/TaniumClient/Tools 2>/dev/null | head -100"
shell_run 10-tanium-client.txt "echo '=== CX logs ==='; find ${TANIUM_DIR} -type f -name '*.log' -path '*xtension*' 2>/dev/null | head -20"
shell_run 10-tanium-client.txt "echo '=== client settings (registration / server) ==='; ${TANIUM_DIR}/TaniumClient/TaniumClient config list 2>&1 | head -60"
shell_run 10-tanium-client.txt "echo '=== last registration / server name ==='; grep -rhiE 'Registration|ServerName|forward leader|Backward' ${TANIUM_DIR}/TaniumClient/Logs 2>/dev/null | tail -40"

##############################################################################
# PHASE 5 - correlation input: hash reality vs trustdb
##############################################################################
log "--> phase 5: hash reality"
shell_run 11-hash-reality.txt "echo '=== on-disk sha256 + size for Tanium executables/libs (compare against 06-trustdb.txt) ==='; for f in \$(find ${TANIUM_DIR} -xdev -type f \\( -perm /111 -o -name '*.so*' \\) 2>/dev/null | head -150); do s=\$(stat -c %s \"\$f\" 2>/dev/null); h=\$(sha256sum \"\$f\" 2>/dev/null | cut -d' ' -f1); printf '%s %s %s\\n' \"\$f\" \"\$s\" \"\$h\"; done"

##############################################################################
# Package it
##############################################################################
{
  echo "host:        $(hostname -f 2>/dev/null || hostname)"
  echo "collected:   $(date -u +%FT%TZ) (UTC)"
  echo "collector:   collect-fapolicyd-tanium-evidence.sh"
  echo "TANIUM_DIR:  ${TANIUM_DIR}"
  echo "SINCE:       ${SINCE}"
  echo "AUSEARCH_TS: ${AUSEARCH_TS}"
  echo "uid:         $(id -u) ($(id -un))"
  echo
  echo "Files:"
  ls -l "$OUT"
} > "$OUT/00-MANIFEST.txt"

TARBALL="${OUT}.tar.gz"
tar czf "$TARBALL" -C "$(dirname "$OUT")" "$(basename "$OUT")" 2>/dev/null
chmod 600 "$TARBALL" 2>/dev/null

log ""
log "==> DONE"
log "==> directory: $OUT"
log "==> tarball:   $TARBALL"
log ""
log "Review before sharing: Tanium logs and client config may contain"
log "hostnames, server FQDNs, and site identifiers."
