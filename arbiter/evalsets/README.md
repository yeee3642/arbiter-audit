# Evaluation sets

| file | n | provenance | complete? |
|---|---:|---|---|
| `v3_authored.json` | 40 | authored for this project | yes — carries the head-to-head results |
| `v1_paired14.json` | 14 | mixed: authored CTF, a deployed honeypot, OpenZeppelin v5, third-party audit samples | **7 of 14 snippets withheld** |
| `authored_pairs.json` | — | authored | yes |
| `test_pairs_v2.json` | — | authored, round-2 split | yes |

## Why 7 snippets are withheld

`v1_paired14.json` backs the baseline-instrument analysis (the TN=0 result, detector
saturation, per-detector discriminative power). Seven of its entries are third-party
code carrying findings that have **not completed vendor disclosure**, so the snippet and
its mechanism notes are withheld. Each withheld entry keeps `code_sha256` of the exact
snippet used in the published measurements, so every number stays verifiable and the set
can be restored byte-identical once disclosure closes.

The head-to-head comparison in `RESULTS.md` does not use this file — it runs on
`v3_authored.json`, which is authored end to end and is published complete.
