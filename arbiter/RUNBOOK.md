# Running ARBITER on the infra box

Everything below is run on `ubuntu@<infra-host>`, where the tool, the dependency
cache and OneSavie's dataset all already live. Nothing here needs a local checkout.

## 0. Connect

```bash
ssh -i <path-to-your-key>/<your-key>.pem ubuntu@<infra-host>
```

The key path depends on the shell, and this is where it usually goes wrong:

| shell | path |
| --- | --- |
| Git Bash | `/c/Users/<you>/<your-key>.pem` |
| WSL | `/mnt/c/Users/<you>/<your-key>.pem` |
| PowerShell / cmd | `C:\Users\<you>\<your-key>.pem` |

WSL can refuse a key that lives on `/mnt/c`, because that mount reports mode 777.
Copy it in once and the problem goes away for good:

```bash
cp /mnt/c/Users/<you>/<your-key>.pem ~/kp.pem && chmod 600 ~/kp.pem
```

## 1. Two environment variables, every session

```bash
export PATH="$HOME/.foundry/bin:$PATH"
export AIS3_API_KEY=<the gateway key>
cd ~/rig/arbiter
```

`forge` is not on the default PATH, and the gateway key is never read from a file in
the repository -- a run without it fails immediately rather than silently doing nothing.
The key is not written down here either, for the same reason; it lives in whatever
password manager or shell profile you keep it in.

## 2. What is already running

```bash
ps -eo pid,etime,cmd | grep "[p]ython3 cli"
ls -t ~/*.log | head
```

Runs are started detached with `setsid`, so they survive the ssh session dropping. To
stop one, match on its run id and nothing else:

```bash
pkill -f "run-id vloss4"
```

Never `pkill` on a pattern that also appears in the command you are typing: over ssh the
whole command line is visible in `ps`, so a pattern like `cli.py audit` kills the shell
that is about to launch it. That has happened twice.

## 3. Audit a repository

```bash
bash scripts/launch_audit.sh <run-id> <turns> <attempts> <workers> <rpm> <repo>...
```

```bash
bash scripts/launch_audit.sh myrun 18 2 16 70 ~/Bastet/dataset/repos/2022-04-axelar
```

Contracts with nothing to attack -- interfaces, type libraries, test scaffolding -- are
skipped, and what was skipped is written to `runs/<run-id>.skipped.json`. Pass
`--all-files` to the CLI directly if that is not wanted.

## 4. Run against a labelled evaluation set

```bash
bash scripts/launch_run.sh <run-id> <evalset> <turns> <attempts> <workers> <rpm>
```

```bash
bash scripts/launch_run.sh myeval evalsets/v4_test.json 26 2 16 70
```

`evalsets/v4_test.json` is the held-out set: 70 samples, 35 vulnerable and 35 patched,
every pair machine-verified so a false positive is unambiguous.

## 5. Watch it

```bash
tail -f ~/<run-id>.log                       # live
grep MISS ~/<run-id>.log                     # only the disagreements
wc -l runs/<run-id>.ledger.jsonl             # gateway requests spent
```

A row appears only when a sample has finished all its attempts, so with
`--attempts 2 --max-turns 26` the first ones take several minutes. Runs are resumable:
relaunch with the same run id and finished samples are skipped.

## 6. Score it

```bash
python3 cli.py score --summary runs/<run-id>.summary.json --evalset evalsets/v4_test.json
```

Against OneSavie's own twenty scored rows, asking the question its evaluator actually
asks -- does this repository contain a finding of this class:

```bash
python3 cli.py eval --results runs/<run-id>.results.jsonl \
  --truth ~/Bastet/evaluation_results.csv --tag Slippage
```

## 7. Get the exploits out

```bash
python3 cli.py dump --results runs/<run-id>.results.jsonl --out /tmp/ex \
  --evalset evalsets/v4_test.json
```

Each proven finding becomes a self-contained Foundry project, and `dump` runs every one
of them before reporting, so `reproduces` in `manifest.json` is measured rather than
claimed. To reproduce one by hand:

```bash
cd /tmp/ex/<project> && forge test -vvv
```

## 8. Check the harness itself, without spending a request

All of these are pure CPU and take seconds:

```bash
python3 scripts/forgery_probe.py     # an attack may not forge authority with cheatcodes
python3 scripts/victim_probe.py      # a drain is harm; taking back a donation is not
python3 scripts/halt_probe.py        # an exploit must satisfy the predicate, not escape it
python3 scripts/drain_probe.py       # value must leave the contract under audit
python3 scripts/sweep_probe.py       # right mechanism at the wrong scale is still found
python3 scripts/context_probe.py --triaged $(cat /tmp/allrepos.txt)   # compile coverage
```

And to re-audit every exploit the project has ever called proven:

```bash
python3 scripts/audit_proofs.py --workers 8 && python3 scripts/audit_summary.py
```

## Where things are

| path | what |
| --- | --- |
| `~/rig/arbiter` | the tool, evalsets, runs, scripts |
| `~/rig/arbiter/runs/` | `<id>.results.jsonl`, `<id>.summary.json`, `<id>.ledger.jsonl` |
| `~/soldeps` | vendored Solidity dependencies, 13 packages |
| `~/Bastet` | OneSavie's repository and its 338 dataset repositories |
| `~/<run-id>.log` | run output |

## Cost

The gateway rations requests, not tokens: 120 rpm on a shared key. A run costs at most
`samples x attempts x turns` requests, so 70 samples at 2x26 is about 3,600 -- roughly an
hour at `--rpm 70`. Keep one run in flight at a time; two will collide on the limit and
spend the budget on 429s.
