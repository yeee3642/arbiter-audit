#!/usr/bin/env bash
# Launch an ARBITER audit detached from the ssh session that started it.
#
# In its own file rather than inline, for a reason learned the hard way: a `pkill -f`
# whose pattern appears in the launching command line kills the launching shell too, and
# an inline `nohup ... &` inside an ssh -c string puts the whole run in that string.
#
#   launch_audit.sh <run-id> <turns> <attempts> <concurrency> <rpm> <repo> [repo...]
set -u

RUN_ID="$1"; shift
TURNS="$1"; shift
ATTEMPTS="$1"; shift
CONC="$1"; shift
RPM="$1"; shift

export PATH="$HOME/.foundry/bin:$PATH"
: "${AIS3_API_KEY:?set AIS3_API_KEY before launching}"

cd "$HOME/rig/arbiter" || exit 1
LOG="$HOME/${RUN_ID}.log"

setsid python3 cli.py audit "$@" \
  --run-id "$RUN_ID" \
  --attempts "$ATTEMPTS" \
  --max-turns "$TURNS" \
  --concurrency "$CONC" \
  --rpm "$RPM" > "$LOG" 2>&1 < /dev/null &

echo "launched $RUN_ID (pid $!) -> $LOG"
