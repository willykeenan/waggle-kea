# Waggle + Kea research package

This directory contains William Keenan's public research materials for Waggle
and Kea. It accompanies the deterministic, fixture-only TypeScript reference
implementation in the repository root.

## Research question

Can machine-to-machine coordination use typed state deltas and registered
content references while remaining inspectable, replayable, and explicitly
separated from authority to act?

## What the evidence currently supports

- Four canonical fixture packets round-tripped exactly through the reference
  codec in the earlier fixture evaluation.
- A bounded six-branch local experiment restored one Qwen3-14B native prefix
  state into a resident Apple Metal context and preserved exact task outputs.
- The resident-native arm crossed the repeated full-text arm after branch two.
- It did **not** beat the stronger cached-prefix text control or the warmed
  fresh-native control, so the overall-efficiency claim was rejected.
- Every public reference-implementation test executes with zero model calls,
  network calls, and authority effects.
- The separately preregistered v0.3 decision-sufficiency study safely qualified
  35,013/36,600 frozen case-policy decisions with zero action mismatches, but
  retained the null because its gain over safe `k=1` missed the frozen gate.

The negative result is part of the release. It keeps an attractive mechanism
separate from an unsupported performance claim.

## Contents

| File | Purpose |
| --- | --- |
| [`PAPER.md`](PAPER.md) | Concise manuscript for scholarly review and future preprint submission |
| [`RESEARCH-METHOD.md`](RESEARCH-METHOD.md) | Public evaluation, admission, falsification, and release method |
| [`CLAIM-LEDGER.md`](CLAIM-LEDGER.md) | Allowed wording, evidence class, and explicit non-claims |
| [`RESULTS-C15D.md`](RESULTS-C15D.md) | Bounded local model/hardware result, controls, and limitations |
| [`data/c15d-summary.json`](data/c15d-summary.json) | Machine-readable aggregate of the reported experiment |
| [`verify.mjs`](verify.mjs) | Offline structural and claim-boundary verifier |
| [`../benchmarks/decision-sufficiency/`](../benchmarks/decision-sufficiency/RESULT.md) | Public v0.3 protocol, complete decision evidence, controls, negative verdict, and independent verifier |

## Verify locally

From the repository root:

```bash
npm install
npm run verify:research
```

The verifier checks the machine-readable result, the negative-control outcome,
the authorship metadata, and the absence of private implementation markers.
`SHA256SUMS` binds the public research files after each release.

## Reproducibility boundary

The reference protocol, validators, deterministic fixtures, tests, and public
aggregate are open source. The raw model-native state and full experiment
implementation are not published. This is therefore an inspectable aggregate
and reference implementation, not a third-party replication package.

## Citation and license

Citation metadata is provided in [`CITATION.cff`](CITATION.cff). Research text
and aggregate data in this directory are licensed under CC BY 4.0; the source
code in the repository root is MIT licensed.
