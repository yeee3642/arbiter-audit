# Generate broadly, judge strictly

Arm B was a disappointment and the reason turned out to be architectural rather than
evidential. An adversarial review put it in one sentence: **the gates are monotone
rejectors, and they were wired into the generator.** Arm B found five true positives arm A
never found and lost ten. A filter cannot do that. The gates were not merely deciding what
to accept, they were changing what the agent went looking for -- a thing that can only
ever say no belongs outside the loop.

Attack surface and evidential standard had been fighting over one knob. Separate them:
take the UNION of what either configuration ever proved, and apply the gates afterwards.

|  | TP | TN | FP | FN | prec | rec | spec | f1 | mcc |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| arm A as it ran | 15 | 22 | 13 | 20 | 0.536 | 0.429 | 0.629 | 0.476 | 0.058 |
| arm B as it ran | 10 | 31 | 4 | 25 | 0.714 | 0.286 | 0.886 | 0.408 | 0.214 |
| union, ungated | 20 | 20 | 15 | 15 | 0.571 | 0.571 | 0.571 | 0.571 | 0.143 |
| **union, behind the gates** | **18** | **26** | **9** | **17** | **0.667** | **0.514** | **0.743** | **0.581** | **0.264** |

The last row beats arm A on every metric and beats arm B on recall, f1 and mcc. Paired
bootstrap against arm A, 20,000 draws:

| | difference | 95% interval | |
| --- | ---: | --- | --- |
| precision | +0.131 | [+0.035, +0.249] | excludes zero |
| f1 | +0.104 | [+0.001, +0.216] | excludes zero |
| mcc | +0.206 | [+0.052, +0.378] | excludes zero |
| recall | +0.085 | [−0.031, +0.214] | includes zero |

Three of four exclude zero, and recall -- the thing arm B surrendered -- is not lost. This
is the first comparison in this project that is separated from noise. Arm B's own
pre-registered result was that nothing was separated at n=70; the same n, the same
samples and the same gates give a separated result once the gates are moved out of the
generator, which is the finding.

## What this is, and what it is not

It is an ablation over two completed runs, and every number is recomputed by
`scripts/cascade.py` from the two result files plus the per-sample gate verdicts in
`scripts/recheck_verdicts.py`. Nothing here needed a new gateway request.

It is **not** a measured system. A tool built this way -- run several configurations,
union their attacks, gate the union -- has not been run end to end, and doing so would
cost roughly double the requests of one arm. The claim supported is about where the gates
belong, not about a shipped pipeline.

Two further caveats, stated rather than left to be found. The union inherits both arms'
labels, and one pair in this benchmark is inverted outright, so a small amount of the
remaining error is label noise rather than tool error. And the union of two arms is not
free: it is two runs, and the honest cost axis for this project has always been gateway
requests, not wall-clock.
