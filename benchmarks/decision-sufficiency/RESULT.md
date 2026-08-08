# Certified task-sufficient prediction handoffs: v0.3 result

Author: William Keenan

Status: accepted Trial 6; preregistered prospective secondary analysis

Scientific verdict: `H0_RETAINED`

## Result in one sentence

An integer-exact partial-vector certificate preserved every qualified
full-vector decision and safely covered 95.66% of 36,600 case-policy decisions,
but its 6.65-point coverage gain over the safe one-component control missed the
preregistered 10-point gate, and a simpler expected-cost summary was smaller.

## What was tested

- 3,050 frozen, train-disjoint BANKING77 test cases;
- one previously evaluated 77-class classifier;
- 12 deterministic, output-blind four-action cost policies;
- 36,600 complete case-policy decisions;
- adaptive certificates revealing at most 8 probabilities;
- safe fixed `k=1` and `k=3`, naive top-1, full-vector, expected-cost-summary,
  and no-state controls; and
- standalone Kea qualification plus a fresh restricted consumer process.

This is a prospective secondary analysis of an existing classifier and test
population, not an independent model replication.

## Primary outcome

| Frozen gate | Observed | Pass |
| --- | ---: | :---: |
| Adaptive safe coverage at least 90% | 95.6639% (`35,013/36,600`) | Yes |
| Gain over safe `k=1` at least 10 points | +6.6475 points | **No** |
| Adaptive action mismatches | 0 | Yes |
| Full-vector reconstruction mismatches | 0 | Yes |
| Expected-cost-summary mismatches | 0 | Yes |
| Naive top-1 mismatches at least 1 | 421 | Yes |
| No-state continuations | 0 | Yes |
| Specified attacks rejected | All | Yes |
| Provider/model API calls and authority effects | 0 | Yes |

The case-clustered 95% bootstrap interval for adaptive safe coverage was
`[95.0301%, 96.2541%]`. The interval for gain over safe `k=1` was
`[+5.8552, +7.4536]` percentage points. Because every frozen gate was required,
the correct verdict is `H0_RETAINED`.

## Secondary findings

Safe coverage increased monotonically with the reveal budget:

| Maximum revealed components | Safe coverage |
| ---: | ---: |
| 1 | 89.0164% |
| 2 | 90.9016% |
| 3 | 92.6967% |
| 4 | 93.7732% |
| 5 | 94.4481% |
| 6 | 94.9536% |
| 7 | 95.3607% |
| 8 | 95.6639% |

Among the frozen certificate rows, the median revealed count was 1 and the
95th percentile was 7. Unresolved cases refused rather than substituting a
nominal top-class decision.

The byte comparison did not favor the complete certificate path:

| Representation | Median canonical bytes |
| --- | ---: |
| Four-action expected-cost summary | 390 |
| Full 77-component vector | 491.5 |
| Partial certificate | 680 |
| Complete Waggle message envelope | 1,701 |

The certificate's value in this experiment is its independently checkable
all-completions proof and explicit refusal boundary, not compression. The
expected-cost summary is the strongest compact informed control and was both
decision-exact and smaller.

## Why the certificate is exact

For candidate action `a`, opponent `b`, revealed indices `R`, omitted indices
`O`, and omitted mass `r`, the certificate computes

`L(a,b) = sum(i in R) p[i](C[b,i] - C[a,i]) + r min(i in O)(C[b,i] - C[a,i])`.

The omitted contribution is linear over a probability simplex, so its minimum
occurs by placing all omitted mass on an omitted label with the smallest cost
difference. A candidate is certified only when `L(a,b) > 0` for every opponent.
The implementation's bound was also checked exhaustively on small integer
simplices.

This establishes the first certifying prefix in the frozen reveal order. It
does not establish the globally smallest subset or a minimum universal
message.

## Independent verification and consumer boundary

The zero-model verifier independently regenerated the policies and recomputed
all certificates, bounds, controls, coverage values, bootstrap intervals,
content IDs, byte counts, attacks, and the primary verdict. A fresh process
then consumed one Kea-qualified projection without receiving source text, the
true label, or the full probability vector.

Trial 1 stopped before evaluation because of a cross-runtime number-identity
boundary. Trial 2 completed the scientific output but exposed two independent
verifier assumptions. Trials 3 and 4 stopped before new output while those
verifier fixtures were corrected. Trial 5 reproduced and independently audited
the scientific result, then exposed a final full-receipt versus reduced-sample
comparison. All failed freezes and artifacts are preserved; Trial 6 changed no
scientific input, threshold, or result and passed every verifier.

## Reproduce and inspect

```bash
npm ci
npm run reproduce
npm run benchmark:decision-sufficiency
npm run benchmark:decision-sufficiency -- --offline
```

The first benchmark command acquires only the pinned, digest-verified public
source files; the second demonstrates that scoring and verification can then
run offline.

The committed reference package is in [`results/reference-v1/`](results/reference-v1/).
`evaluation.json` holds the durable metrics and verdict; `decisions.jsonl.gz`
contains all 36,600 decision rows; `SHA256SUMS` binds the package.

## Non-claims

This result does not establish a globally minimum message, semantic
compression, hidden-state transfer, learned language, privacy, security against
an authenticated malicious writer, cross-model or cross-dataset generalization,
token or credit savings, economic or energy savings, overall efficiency,
production readiness, autonomous authority, or quantum behavior.
