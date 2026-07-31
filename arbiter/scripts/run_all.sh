#!/usr/bin/env bash
# Everything ARBITER can do, in one command, in the order the argument is made.
#
#   run_all.sh <run-id> [--quick]
#
# --quick stops after the stages that cost no gateway requests, which is every claim
# about the harness itself. Those take about a minute and are what to run before a demo.
# The full form then spends roughly 3,600 requests -- about an hour -- on the paired
# benchmark, which is the only stage that can say whether the tool is any good.
#
# Resumable: relaunch with the same run id and finished samples are skipped.
set -u

RUN_ID="${1:-all}"
QUICK=""
[ "${2:-}" = "--quick" ] && QUICK=1

export PATH="$HOME/.foundry/bin:$PATH"
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
RESULTS="$HOME/${RUN_ID}-report.txt"
: > "$RESULTS"

say() { printf '\n=== %s\n' "$1" | tee -a "$RESULTS"; }
note() { tee -a "$RESULTS"; }

say "0. toolchain"
{ forge --version | head -1; python3 --version; } | note

# ---------------------------------------------------------------------------
# Stage 1 -- the harness checks itself. No model, no gateway, no network.
# Each probe asserts something in BOTH directions: the thing it refuses must be
# refused, and the thing it must not refuse must still pass. A gate that only ever
# says no is not a gate, it is a broken tool.
# ---------------------------------------------------------------------------
say "1. integrity gates (zero gateway requests)"
for probe in forgery victim halt drain sweep collide economy contention; do
  printf '  %-10s ' "$probe" | note
  python3 "scripts/${probe}_probe.py" 2>&1 | grep -E "as expected" | note || echo "FAILED" | note
done

# ---------------------------------------------------------------------------
# Stage 2 -- can the tool compile real audit repositories at all. This was 0/975
# before the resolver existed, and no evidence of any kind is possible without it.
# ---------------------------------------------------------------------------
say "2. compile coverage on real repositories"
if [ ! -f /tmp/allrepos.txt ]; then
  python3 - > /tmp/allrepos.txt <<'PY'
import csv, os
seen = []
path = os.path.expanduser("~/Bastet/evaluation_results.csv")
for row in csv.DictReader(open(path, encoding="utf-8-sig")):
    name = row["file_name"].strip()
    if name not in seen:
        seen.append(name)
root = os.path.expanduser("~/Bastet/dataset/")
print(" ".join(root + n for n in seen))
PY
fi
python3 scripts/context_probe.py --triaged --workers 8 $(cat /tmp/allrepos.txt) 2>&1 \
  | grep -E "compiles|top failure" -A1 | head -6 | note

# ---------------------------------------------------------------------------
# Stage 3 -- re-audit every exploit the project has ever called proven, including
# the negation test: run it again with the attack deleted, and refuse it if the
# predicate still holds. This is the stage that found 25 false positives.
# ---------------------------------------------------------------------------
say "3. audit of past proofs"
python3 scripts/audit_proofs.py --workers 8 > /tmp/audit_run.txt 2>&1
python3 scripts/audit_summary.py 2>&1 | head -9 | note

if [ -n "$QUICK" ]; then
  say "stopping after the request-free stages (--quick)"
  echo "report: $RESULTS" | note
  exit 0
fi

# ---------------------------------------------------------------------------
# Stage 4 -- the experiment. Same 70 paired samples, same model, same turn budget
# and attempt count as the recorded arm that used the retired predicates, so the
# only difference is the gates. A false positive here is unambiguous: the exploit
# ran against the fixed half of a pair.
# ---------------------------------------------------------------------------
say "4. paired benchmark, 70 samples (this is the slow one)"
: "${AIS3_API_KEY:?set AIS3_API_KEY before running the full pipeline}"
python3 cli.py run \
  --evalset evalsets/v4_test.json \
  --model ais3/nemotron-3-ultra-550b \
  --run-id "$RUN_ID" \
  --attempts 2 --max-turns 26 --concurrency 16 --rpm 70 2>&1 | tail -4 | note

say "5. score, against the arm that used the retired predicates"
echo "  baseline (eth_profit/token_profit/state_change):" | note
echo "    TP 15  TN 22  FP 13  FN 20   precision 0.536  mcc 0.058" | note
echo "  this run:" | note
python3 cli.py score --summary "runs/${RUN_ID}.summary.json" \
  --evalset evalsets/v4_test.json 2>&1 | head -14 | note

# ---------------------------------------------------------------------------
# Stage 6 -- the deliverable. Every proven finding becomes a project anyone can
# run, and dump runs each one before reporting, so "reproduces" is measured.
# ---------------------------------------------------------------------------
say "6. exploits"
python3 cli.py dump --results "runs/${RUN_ID}.results.jsonl" \
  --out "/tmp/${RUN_ID}-exploits" --evalset evalsets/v4_test.json 2>&1 | head -12 | note

say "done"
echo "report:   $RESULTS" | note
echo "exploits: /tmp/${RUN_ID}-exploits" | note
