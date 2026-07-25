# Everything here runs without an API key and without the corpus, except where
# noted. That boundary is the point: the claims that do not need the corpus
# should be checkable by anyone reading the repository.

PY ?= python
CC := bastet-cc

.PHONY: help install test check audit figures power scrub hooks reproduce structural clean

ROUTED ?= d1_routed_dev1
BCAST  ?= d1_broadcast_dev1

help:
	@echo "install     editable install + dev extras"
	@echo "hooks       enable the credential guard (do this first)"
	@echo "test        run the test suite"
	@echo "check       test + credential scan + leakage audit  (the pre-commit gate)"
	@echo "reproduce   regenerate every corpus-free number, and name what it skipped"
	@echo "structural  label-free routed-vs-broadcast head-to-head"
	@echo "audit       leakage + instrument audits            (needs data/train.csv)"
	@echo "power       what effect size the TEST design can resolve"
	@echo "figures     rebuild every figure from artefacts on disk"
	@echo "scrub       dry-run the credential scrubber over runs/"

install:
	$(PY) -m pip install -e "$(CC)[dev]"

hooks:
	git config core.hooksPath .githooks
	@echo "credential guard enabled"

test:
	cd $(CC) && $(PY) -m pytest

# The gate. Ordered cheapest-first so a failure reports fast.
check: test scrub
	@echo "--- leakage audit ---"
	@cd $(CC) && $(PY) scripts/leakage_audit.py || \
		echo "(leakage audit needs data/train.csv for the thin-tag section)"

scrub:
	@cd $(CC) && $(PY) scripts/scrub_artifacts.py --audit

structural:
	cd $(CC) && $(PY) -m bastet_cc.cli structural --a $(ROUTED) --b $(BCAST) \
		--out runs/compare/d1_structural.json

# Regenerates every artefact whose inputs are already in the repository, then
# names the ones it could not. The README claims "nothing is estimated"; this is
# how a reader checks that, and the skip list is printed rather than implied so
# the boundary between "verified here" and "needs the corpus" stays visible.
reproduce: test structural
	@echo "--- upstream null test (re-derives summary.json from runs.jsonl) ---"
	cd $(CC) && $(PY) scripts/upstream_null_test.py --analyse
	@echo "--- leakage audit (rules 2/3; rule 1 needs train.csv) ---"
	-cd $(CC) && $(PY) scripts/leakage_audit.py
	@echo "--- figures ---"
	cd $(CC) && $(PY) -m bastet_cc.cli figures
	@echo
	@echo "NOT regenerated here -- these need data/train.csv or the extracted corpus:"
	@echo "  runs/e6/            perfect-predictor ceiling   (scripts/e6_scorer_forensics.py)"
	@echo "  runs/instrument/    floor, metric flip, balance (scripts/instrument_audit.py)"
	@echo "  runs/routing_recall/ routing recall ceiling     (scripts/routing_recall_ceiling.py)"
	@echo "  runs/e7/            memorisation probe          (needs an API key too)"
	@echo "  the cost ladder     bastet-cc route over the corpus"

audit:
	cd $(CC) && $(PY) -m bastet_cc.cli audit

power:
	cd $(CC) && $(PY) -m bastet_cc.cli power --decisions 240 --discordance 0.25

figures:
	cd $(CC) && $(PY) -m bastet_cc.cli figures

clean:
	find . -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
	rm -rf $(CC)/.pytest_cache
