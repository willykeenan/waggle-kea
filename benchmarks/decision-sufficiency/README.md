# Decision-sufficiency benchmark

This benchmark asks a narrow question: when a model has produced a 77-class
probability vector and a downstream four-action cost policy is fixed, can a
producer reveal only a prefix of the probabilities while giving another
process an exact proof that every completion of the omitted mass selects the
same action?

Read [`PROTOCOL.md`](PROTOCOL.md) before interpreting results. This is a
preregistered prospective secondary analysis of the already evaluated
BANKING77 classifier and population. It is not an independent model
replication.

## Reproduce

From the repository root:

```bash
npm ci
npm run benchmark:banking77
npm run benchmark:decision-sufficiency
```

The second command creates the pinned Python environment and verified source
cache. The decision-sufficiency runner can subsequently be forced offline:

```bash
npm run benchmark:decision-sufficiency -- --offline
```

Normal reproduction writes to the ignored `results/local-v1/` directory. The
committed `results/reference-v1/` package is checked with:

```bash
npm run verify:decision-sufficiency
```

## Evidence package

The result package contains content-addressed, text-free prediction vectors;
deterministic cost policies; gzip-compressed complete case-policy decisions;
readable certificate samples; a content-addressed run receipt; runtime facts;
attack results; durable primary and secondary metrics; and SHA-256 checksums.

The verifier independently reconstructs all 36,600 case-policy certificates,
full-vector and compact-control decisions, qualification IDs, consumer
outcomes, byte measurements, bootstrap intervals, and the primary verdict.
A fresh restricted consumer process receives only one certificate, policy,
qualification, and authority-false flag—never source text, a true label, or the
full vector.

The expected-cost summary is the strongest compact informed control. If it is
smaller than the Waggle certificate, that is reported as a control advantage,
not hidden as a favorable encoding comparison.
