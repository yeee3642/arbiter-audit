#!/usr/bin/env bash
# The demo, as one command, so recording it is: start the screen recorder, run this.
#
# Everything here is deterministic and offline. Nothing calls the gateway, so nothing in
# it can fail on stage for a reason outside the room -- which matters, because the one
# part that DOES call the gateway finds the bug in roughly one run of three, and a live
# audit is therefore the one thing not to put in front of a judge.
#
#   scripts/demo.sh              pause between acts, for narrating
#   scripts/demo.sh --auto       fixed pauses, for an unattended recording
#   scripts/demo.sh --dump DIR   use a specific `arbiter dump` directory in act 3
set -u

AUTO=""
DUMP="$HOME/exploits-casc2"
while [ $# -gt 0 ]; do
    case "$1" in
        --auto) AUTO=1; shift ;;
        --dump) DUMP="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
[ -f "$HOME/.arbiter_env" ] && source "$HOME/.arbiter_env"

if ! command -v forge >/dev/null 2>&1; then
    echo "forge is not on PATH. Every act below produces evidence by executing it."
    exit 2
fi

B=$(printf '\033[1m'); D=$(printf '\033[2m'); R=$(printf '\033[0m')

act() {
    printf '\n%s%s\n%s\n%s\n' "$B" "$(printf '=%.0s' $(seq 70))" "  $1" "$(printf '=%.0s' $(seq 70))$R"
    [ -n "${2:-}" ] && printf '%s  %s%s\n' "$D" "$2" "$R"
    echo
}

pause() {
    if [ -n "$AUTO" ]; then sleep "${1:-6}"; else
        printf '\n%s  [enter]%s ' "$D" "$R"; read -r _ || true
    fi
}

# Every act has to produce output. Found while rehearsing: one script was missing from
# this machine, `2>&1 | head` swallowed the error into the pipe, and the section printed
# its heading, nothing else, and moved on with exit 0. A demo that can show an empty
# section and call it a success is the same defect this project exists to stop shipping.
show() {
    local out
    out=$("$@" 2>&1)
    if [ -z "$out" ]; then
        printf '  !! %s produced NO OUTPUT -- this act did not run.\n' "$1" >&2
        return 1
    fi
    printf '%s\n' "$out"
}

# ---------------------------------------------------------------------------------
act "0.  The claim" \
    "A finding is a transcript of an execution, not an assertion. The model is not"
cat <<'TXT'
  allowed to report a vulnerability. It has to write an attack, and this harness
  compiles it and runs it on an EVM against a success condition the model never sees.

  Everything after this point is that sentence being checked.
TXT
pause 8

# ---------------------------------------------------------------------------------
act "1.  The gates check themselves" \
    "No gateway, no network, no API key. 60 seconds."
for p in victim forgery halt drain sweep latebinding setup_forgery gain; do
    printf '  %-16s ' "$p"
    python3 "scripts/${p}_probe.py" 2>&1 | tail -1
done
cat <<'TXT'

  Each probe asserts in BOTH directions: the thing it must refuse is refused, AND the
  thing it must not refuse still passes. A gate that only ever says no is not a gate.
TXT
pause 8

act "1b. One of them in full" "forgery_probe: what the attack may and may not do"
show python3 scripts/forgery_probe.py | tail -9
cat <<'TXT'

  The last two lines are the point. Cheatcodes are refused in the ATTACK and allowed in
  SETUP, because setup has to build a world before anything can happen in it.
TXT
pause 8

# ---------------------------------------------------------------------------------
act "2.  A real attack, on a real chain" \
    "anvil. Real keys, real gas, and no cheatcode exists over JSON-RPC."
show python3 scripts/live_attack.py --port 8599 | tail -14
pause 10

act "2b. The same attack, one line moved" \
    "nonce written BEFORE the transfer instead of after. Nothing else changes."
show python3 scripts/live_attack.py --port 8600 --patched | tail -12
cat <<'TXT'

  Identical attacker contract, identical accounts, identical amounts. An exploit that
  drained both would never have been about the defect.
TXT
pause 10

# ---------------------------------------------------------------------------------
if [ -d "$DUMP" ]; then
    act "3.  The evidence ladder" \
        "Each finding walked from the harness, to a standalone project, to a chain."
    show python3 cli.py prove --dump "$DUMP" | tail -20
    cat <<'TXT'

  The rungs are not redundant, and the asymmetry is the whole design: rung 1 is the only
  one that searches. Rung 3 cannot find anything at all -- it can only refuse.
TXT
    pause 12
else
    act "3.  The evidence ladder -- SKIPPED" \
        "No dump directory at $DUMP. Run: cli.py dump --results <run> --out <dir>"
fi

# ---------------------------------------------------------------------------------
act "4.  What the baseline produces" \
    "Its 53 detectors on the same 40 samples, scored per detector."
ADJ=$(show python3 scripts/adjudicability.py --jobs runs/h2h-bastet.jobs.jsonl) || exit 1
echo "$ADJ" | head -12
echo "$ADJ" | tail -17
pause 12

# ---------------------------------------------------------------------------------
act "5.  Our own ceiling" \
    "The 35 reference exploits, composed under the predicate WE are graded with."
show python3 scripts/ceiling_probe.py --workers 8 | tail -12
cat <<'TXT'

  Recall is bounded by 0.229, not by 1.000, and three of the four inexpressible classes
  are the predicate being deliberately stricter than "the attacker profited".

  We measured this against ourselves. Nobody asked us to.
TXT
echo
