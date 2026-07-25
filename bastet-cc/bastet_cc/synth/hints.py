"""S3 routing-hint validation: entirely deterministic, no LLM anywhere.

An induced hint is only useful if it (a) actually occurs in real Solidity --
df==0 kills hallucinated identifiers outright -- (b) discriminates: terms in more
than 5% of files route everything and save nothing (same philosophy as
routing.fit's IDF cut), and (c) concentrates in this tag's positive repos
(lift >= 2, and >= 2 distinct positive repos when the tag has >= 3, so a single
repo's private vocabulary cannot masquerade as a tag signature).

Document frequency is measured over all 54 train repos' *code* (per DESIGN §2.3);
positivity labels come exclusively from TRAIN-SYN findings, so no DEV label ever
influences a hint. Tags whose validated hints run dry fall back to a hand-curated
domain lexicon -- every term of which is still forced through the df>0 reality
check before it may appear in a detector.
"""

from __future__ import annotations

import math

MAX_DF_RATIO = 0.05
MIN_LIFT = 2.0
MIN_POS_REPOS = 2       # required when the tag has >=3 positive repos
TOP_HINTS = 8
MAX_HINTS = 12          # ceiling once coverage back-fill starts pulling from the bench
COVERAGE_TARGET = 0.80
MIN_HINTS = 2           # below this a synthesized detector may not ship (no broadcast)

# Third-level fallback (DESIGN §2.3 S3 step 6): domain vocabulary distilled from
# subtag names and protocol interfaces. Curated once by hand; every term is still
# checked df>0 against the train corpus before use, so a stale entry costs nothing.
FALLBACK_LEXICON: dict[str, list[str]] = {
    "Accounting Error": ["totalAssets", "totalSupply", "exchangeRate", "accrue",
                         "totalBorrows", "convertToShares", "convertToAssets",
                         "sharePrice", "totalDebt", "pricePerShare"],
    "Governance": ["propose", "castVote", "quorum", "timelock", "votingPower",
                   "delegate", "proposalThreshold", "getVotes", "votingDelay",
                   "votingPeriod", "queue"],
    "Liquidation": ["liquidate", "healthFactor", "collateralFactor", "seize",
                    "repay", "liquidationBonus", "liquidationThreshold",
                    "collateralRatio", "badDebt", "liquidator"],
    "Cross-Chain": ["lzReceive", "ccipReceive", "dstChainId", "srcChainId",
                    "chainId", "endpoint", "relayer", "bridge", "sendMessage",
                    "crossChain"],
    "MEV": ["deadline", "minAmountOut", "sandwich", "commit", "reveal",
            "block.timestamp", "priorityFee", "slippage"],
    "ERC1155": ["onERC1155Received", "onERC1155BatchReceived",
                "safeBatchTransferFrom", "balanceOfBatch", "uri", "TransferSingle"],
    "DAO": ["propose", "quorum", "ragequit", "shares", "delegate", "member",
            "castVote", "votingPower"],
    "Upgradeable": ["initializer", "initialize", "_authorizeUpgrade", "upgradeTo",
                    "UUPSUpgradeable", "proxiableUUID", "__gap", "Initializable",
                    "_disableInitializers"],
    "ERC777": ["tokensReceived", "tokensToSend", "ERC777", "granularity",
               "defaultOperators", "_callTokensReceived"],
    "Pause": ["pause", "unpause", "whenNotPaused", "whenPaused", "Pausable",
              "paused", "_pause", "_unpause"],
    "Uniswap": ["swapExactTokensForTokens", "getAmountsOut", "IUniswapV2Router02",
                "slot0", "sqrtPriceX96", "IUniswapV3Pool", "getReserves",
                "UniswapV2Library", "exactInputSingle"],
    "TWAP": ["observe", "consult", "twap", "observations", "tickCumulative",
             "secondsAgo", "slot0", "OracleLibrary"],
    "EIP712": ["DOMAIN_SEPARATOR", "_hashTypedDataV4", "EIP712", "hashStruct",
               "ecrecover", "nonces", "TYPEHASH"],
    "Replay Attack": ["nonce", "nonces", "ecrecover", "DOMAIN_SEPARATOR",
                      "signature", "usedSignatures", "deadline"],
    "Bridge": ["finalizeWithdrawal", "messenger", "l1Token", "l2Token",
               "relayMessage", "bridge", "deposits", "withdrawals"],
    "Opensea": ["Seaport", "conduit", "OrderComponents", "fulfillOrder",
                "ConduitController", "zone", "offerer"],
    "Solmate": ["SafeTransferLib", "safeTransferFrom", "safeTransfer",
                "safeApprove", "FixedPointMathLib", "solmate"],
    "Gnosis safe": ["GnosisSafe", "checkSignatures", "execTransaction",
                    "getOwners", "isOwner", "Guard", "fallbackHandler",
                    "enableModule", "threshold"],
    "Zksync": ["zkSync", "L1Messenger", "IZkSync", "l2TransactionBaseCost",
               "requestL2Transaction", "l2TxGasLimit"],
    "Re-org Attack": ["blockhash", "block.number", "confirmations"],
    "Compound": ["Comptroller", "cToken", "CErc20", "exchangeRateStored",
                 "borrowIndex", "claimComp", "accrueInterest", "underlying",
                 "CToken", "redeemUnderlying"],
    "EIP4494": ["permit", "nonces", "DOMAIN_SEPARATOR", "PERMIT_TYPEHASH",
                "tokenId", "getApproved"],
    "Solidity Version": ["selfdestruct", "abi.encodePacked", "ecrecover",
                         "delegatecall", "assembly", "create2"],
}

# Hard AND-gates for category detectors (DESIGN §1.2 required_hints): the file
# must contain these identifiers or the detector never fires. Only tags whose
# defining callback/interface is unambiguous get one; each term is df-checked
# before shipping and dropped if absent from the corpus.
REQUIRED_HINT_CANDIDATES: dict[str, list[str]] = {
    "ERC777": ["tokensReceived"],
    "ERC1155": ["onERC1155Received"],
}


def build_file_sets(repo_indexes: dict[str, dict]) -> dict[str, list[set[str]]]:
    """repo -> list of per-file identifier-union sets (the S3 vocabulary V)."""
    out: dict[str, list[set[str]]] = {}
    for repo, ix in repo_indexes.items():
        sets = []
        for f in ix["files"]:
            s: set[str] = set()
            for fn in f["functions"]:
                s.update(fn.get("identifiers") or [])
            sets.append(s)
        out[repo] = sets
    return out


def _df(hint: str, file_sets: dict[str, list[set[str]]], repos: set[str] | None = None
        ) -> tuple[int, int, int]:
    """(files containing hint, files scanned, distinct repos containing hint)."""
    hit = total = 0
    repo_hits = 0
    for repo, sets in file_sets.items():
        if repos is not None and repo not in repos:
            continue
        in_repo = False
        for s in sets:
            total += 1
            if hint in s:
                hit += 1
                in_repo = True
        repo_hits += int(in_repo)
    return hit, total, repo_hits


def validate_hints(tag: str, candidates: list[str],
                   file_sets: dict[str, list[set[str]]],
                   pos_repos: list[str],
                   localized_ident_sets: list[set[str]]) -> dict:
    """Run the S3 elimination ladder over one tag's candidates.

    Returns {kept, rejected: {hint: reason}, coverage, single_repo_hints,
    fallback_used, backfilled, n_candidates}.

    The two df-based cuts are *hard*: an identifier that occurs nowhere is a
    hallucination and one that occurs everywhere routes everything, and neither
    fact changes no matter how badly a tag needs hints. The lift and
    positive-repo cuts are *soft*: they express a preference against overfitting,
    and measurement showed them starving whole tags -- ERC777 lost 25 of 30
    candidates to the overfit guard alone. Since a detector with no signature
    never fires (recall 0, strictly worse than an overfit hint), soft rejects are
    kept on a bench and pulled back, best-scored first, whenever the coverage
    target or MIN_HINTS would otherwise be missed. What was pulled back is
    recorded, so the honesty of the per-tag report survives.
    """
    pos = set(pos_repos)
    n_files = sum(len(s) for s in file_sets.values())
    n_pos_files = sum(len(file_sets[r]) for r in pos if r in file_sets) or 1

    rejected: dict[str, str] = {}
    # rows are (hint, lift, pos_df, pos_repo_hits)
    survivors: list[tuple[str, float, int, int]] = []
    bench: list[tuple[str, float, int, int]] = []   # soft rejects, same shape
    seen: set[str] = set()
    for h in candidates:
        if h in seen:
            continue
        seen.add(h)
        df, _, _ = _df(h, file_sets)
        if df == 0:
            rejected[h] = "df==0 (hallucinated identifier)"
            continue
        if df / n_files > MAX_DF_RATIO:
            rejected[h] = f"df/N={df / n_files:.3f} > {MAX_DF_RATIO} (no discrimination)"
            continue
        pos_df, _, pos_repo_hits = _df(h, file_sets, pos)
        lift = (pos_df / n_pos_files) / (df / n_files) if df else 0.0
        if lift < MIN_LIFT:
            rejected[h] = f"lift={lift:.2f} < {MIN_LIFT}"
            bench.append((h, lift, pos_df, pos_repo_hits))
            continue
        if len(pos) >= 3 and pos_repo_hits < MIN_POS_REPOS:
            rejected[h] = f"only {pos_repo_hits} positive repo(s) (overfit guard)"
            bench.append((h, lift, pos_df, pos_repo_hits))
            continue
        survivors.append((h, lift, pos_df, pos_repo_hits))

    rank = lambda t: (-(t[1] * math.log1p(t[2])), t[0])
    survivors.sort(key=rank)
    # The bench exists to rescue coverage, and a hint only generalizes to a repo
    # the detector has never seen if it is not one repo's private vocabulary --
    # LORO measured this directly: fold hint sets made of single-repo identifiers
    # routed zero tasks onto the held-out repo. So cross-repo breadth outranks the
    # lift score here, unlike in the survivor ranking where every entry already
    # cleared the guard.
    bench.sort(key=lambda t: (-t[3], *rank(t)))
    kept = [h for h, *_ in survivors[:TOP_HINTS]]
    # Bench order: demoted survivors first (they cleared every cut), then the
    # soft rejects, so a relaxation is only ever spent when nothing cleaner is left.
    pool = [h for h, *_ in survivors[TOP_HINTS:]] + [h for h, *_ in bench]

    def coverage(hints: list[str]) -> float:
        if not localized_ident_sets:
            return 1.0
        hs = set(hints)
        hit = sum(1 for s in localized_ident_sets if s & hs)
        return hit / len(localized_ident_sets)

    # With no localized evidence the coverage test is vacuously satisfied, so it
    # cannot pull anything back and such a tag would ship on MIN_HINTS alone.
    # Those are exactly the tags with the least evidence, so give them the full
    # top-8 slate instead of the bare minimum.
    floor = MIN_HINTS if localized_ident_sets else TOP_HINTS

    backfilled: list[str] = []
    cov = coverage(kept)
    while (cov < COVERAGE_TARGET or len(kept) < floor) and pool \
            and len(kept) < MAX_HINTS:
        h = pool.pop(0)
        kept.append(h)
        backfilled.append(h)
        cov = coverage(kept)

    fallback_used = False
    if len(kept) < MIN_HINTS:
        # Third-level fallback: domain lexicon (DESIGN §2.3 S3 step 6). df>0 is the
        # reality check; pos_df>0 is preferred, because a term absent from the tag's
        # own positive repos routes the detector everywhere except where it matters.
        fallback_used = True
        lex = FALLBACK_LEXICON.get(tag, [])
        for require_pos in (True, False):
            for h in lex:
                if h in kept or len(kept) >= TOP_HINTS:
                    continue
                df, _, _ = _df(h, file_sets)
                if df == 0:
                    continue
                pos_df, _, _ = _df(h, file_sets, pos) if pos else (1, 0, 0)
                if require_pos and pos_df == 0:
                    continue
                kept.append(h)
            if len(kept) >= MIN_HINTS:
                break
        cov = coverage(kept)

    return {
        "tag": tag,
        "kept": kept,
        "rejected": rejected,
        "backfilled": backfilled,
        "n_candidates": len(seen),
        "n_survivors": len(survivors),
        "coverage": round(cov, 3),
        "single_repo_hints": len(pos) < 3,
        "fallback_used": fallback_used,
    }


def required_hints_for(tag: str, file_sets: dict[str, list[set[str]]],
                       pos_repos: list[str] | None = None) -> list[str]:
    """Category AND-gates that survive the reality check.

    df>0 is not sufficient: `tokensReceived` exists in the corpus but in none of
    the three ERC777-positive TRAIN-SYN repos (the callback lives in the token, and
    only the integrating protocol is in audit scope). Shipping it as an AND-gate
    would guarantee the detector never fires on a repo known to be positive, so a
    gate is only kept when the tag's own positive repos actually contain it.
    """
    out = []
    for h in REQUIRED_HINT_CANDIDATES.get(tag, []):
        df, _, _ = _df(h, file_sets)
        if df == 0:
            continue
        if pos_repos:
            pos_df, _, _ = _df(h, file_sets, set(pos_repos))
            if pos_df == 0:
                continue
        out.append(h)
    return out
