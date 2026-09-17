#!/usr/bin/env bash
#
# controlled-deny-repro.sh -- Phase 3 "smoking gun" capture.
#
# *** THIS SCRIPT STOPS THE fapolicyd SERVICE. CHANGE CONTROL REQUIRED. ***
#
# It stops the daemon, runs a foreground fapolicyd in --permissive
# --debug-deny mode (so nothing is actually blocked but every would-be denial
# is printed with rule/perm/exe/path/ftype/trust), waits for you to reproduce
# the failing Tanium action in another shell, then restores the service.
#
# Safety properties:
#   - permissive mode means the reproduction CANNOT be blocked -> if Tanium
#     still fails here, fapolicyd is not the cause (root-cause class G).
#   - a trap restores the service on Ctrl-C / SIGTERM / error.
#   - NEVER attach gdb/strace/ptrace to fapolicyd: stopping its decision
#     thread wedges every fanotify permission event and hangs the host.
#
set -u

LOG="${LOG:-/var/tmp/fapo-deny-$(date -u +%Y%m%dT%H%M%SZ).log}"
WAIT="${WAIT:-300}"

[ "$(id -u)" -eq 0 ] || { echo "must run as root"; exit 1; }
command -v fapolicyd >/dev/null || { echo "fapolicyd not installed"; exit 1; }

WAS_ACTIVE="$(systemctl is-active fapolicyd 2>/dev/null || true)"
FAPID=""

restore() {
  echo
  echo "==> restoring"
  if [ -n "$FAPID" ] && kill -0 "$FAPID" 2>/dev/null; then
    kill -TERM "$FAPID" 2>/dev/null
    for _ in $(seq 1 20); do kill -0 "$FAPID" 2>/dev/null || break; sleep 0.5; done
    kill -0 "$FAPID" 2>/dev/null && kill -KILL "$FAPID" 2>/dev/null
  fi
  if [ "$WAS_ACTIVE" = "active" ]; then
    systemctl start fapolicyd
    sleep 2
    echo "==> fapolicyd service: $(systemctl is-active fapolicyd)"
  else
    echo "==> fapolicyd was NOT active before this run; leaving it stopped."
  fi
  echo "==> denial log: $LOG"
  echo
  echo "==> Tanium-relevant would-be denials:"
  grep -i tanium "$LOG" 2>/dev/null | head -100 || echo "   (none)"
}
trap restore EXIT INT TERM

echo "==> fapolicyd was: $WAS_ACTIVE"
echo "==> stopping fapolicyd service"
systemctl stop fapolicyd
sleep 2

echo "==> starting foreground fapolicyd --permissive --debug-deny"
echo "==> log: $LOG"
fapolicyd --permissive --debug-deny >"$LOG" 2>&1 &
FAPID=$!
sleep 5

if ! kill -0 "$FAPID" 2>/dev/null; then
  echo "!!! foreground fapolicyd exited immediately. Last lines:"
  tail -40 "$LOG"
  exit 1
fi

cat <<MSG

------------------------------------------------------------------
 fapolicyd is now running in PERMISSIVE + DEBUG-DENY (pid $FAPID).
 Nothing will actually be blocked.

 In ANOTHER shell, reproduce ONE failing Tanium action, e.g.:
   systemctl restart taniumclient
   /opt/Tanium/TaniumClient/TaniumClient --version
   # or ask a single sensor / deploy one tool from the console

 Waiting up to ${WAIT}s. Press Ctrl-C as soon as you are done.
------------------------------------------------------------------

MSG

for _ in $(seq 1 "$WAIT"); do
  kill -0 "$FAPID" 2>/dev/null || break
  sleep 1
done
