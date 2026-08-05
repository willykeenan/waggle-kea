# BANKING77 audited-handoff protocol

Status: exploratory public benchmark

Author: William Keenan

## Research question

On a train-disjoint BANKING77 test set, does a word-and-character classifier
improve intent classification over a matched word-only model, and can Waggle
and Kea transmit its frozen predictions without changing routing decisions
while failing closed on specified detectable faults?

The classifier comparison and handoff comparison are separate estimands. A
classification improvement cannot establish a protocol advantage, and exact
handoff agreement cannot establish better classification.

## Evidence status

This is an exploratory evaluation. Its design was informed by an audit that
inspected aggregate BANKING77 test performance. It is therefore not a
preregistered or confirmatory experiment. The committed protocol, code,
predictions, environment facts, checksums, and complete finite-case handoff
counts make the reference run inspectable and reproducible; they do not make
it independent replication or peer review.

## Population and units

The source is the official BANKING77 train/test release pinned in
`SOURCE.json`. A unit is one normalized, unique, unambiguous customer query.
Normalization lowercases ASCII text, replaces non-alphanumeric runs with one
space, and trims whitespace. It is used only for duplicate and leakage
control; the classifier receives the original text.

The primary test population selects one stable representative per normalized
test group, removes groups with conflicting labels, and removes every group
whose normalized text appears anywhere in raw training data. The official
test result is not promoted over this train-disjoint result.

## Models and matched comparison

The primary comparison changes only the feature representation:

1. word unigram/bigram TF-IDF plus seeded log-loss SGD; and
2. the same word features plus character-boundary 3-5-gram TF-IDF, followed by
   the identical seeded log-loss SGD configuration.

The canonical seed is `20260805`. Four additional prespecified seeds measure
training instability but never select a winner. Majority-class and Complement
Naive Bayes results are sanity baselines. A label-shuffled word-plus-character
model is a leakage/failure control, not a competitive baseline.

## Primary and secondary metrics

The primary estimand is the paired difference in macro-F1 between the
word-plus-character and word-only classifiers under the canonical seed. A
2,000-draw label-stratified paired bootstrap reports a percentile interval.
The exploratory alternative is reported only when the interval's lower bound
is above zero; otherwise the result is `H0_RETAINED`.

Secondary metrics are accuracy, log loss, multiclass Brier score, 15-bin
expected calibration error, top-three accuracy, per-intent precision/recall/F1,
and the complete confidence-threshold risk/coverage curve. No multiplicity
adjustment is applied because no secondary metric is used for a headline
inferential claim.

## Seeded typo stress

For each eligible query, one internal character is deleted from one word of at
least five ASCII letters. The word and position are derived from SHA-256 of the
fixed seed and original text. This is a deterministic sensitivity test of one
artificial corruption family. It is not evidence about natural customer noise,
accessibility, dialects, or production robustness.

## Audited handoff

One frozen prediction record feeds three equally informed receivers:

1. an in-memory direct-record receiver;
2. a canonical-JSON receiver; and
3. a Waggle packet decoded by Kea.

The primary handoff quantity is exact routing disagreement. It must be zero on
every primary case. Each clean Kea interpretation must grant no authority.
Exact duplicates must be idempotent. Stale hashes, byte-count mismatches,
altered envelopes under a reused message ID, manifest mismatches, unknown
codecs, and benchmark-schema violations must fail closed. A no-state consumer
must abstain. One file-ledger tamper must break replay verification.

A fully rehashed forged payload from a permitted writer is deliberately
included as an expected-undetected limitation. Content hashing without a
separate trust root cannot authenticate writer intent. The benchmark is
invalid if it presents this case as detected.

## Valid negative results and kill checks

A non-positive primary interval is a valid scientific result and must not fail
CI. The run is invalid if source hashes or frozen counts drift, train/test
overlap survives filtering, shuffled-label accuracy or macro-F1 exceeds 0.05,
machine-readable evidence is incomplete, any clean handoff changes route, any
specified detectable fault is accepted, the ledger chain fails, or any
authority/provider/external effect occurs during the scored phase.

## Non-claims

This benchmark does not establish:

- performance on private institutional or customer data;
- production routing quality, customer benefit, or operational readiness;
- demographic fairness, accessibility, or regulatory compliance;
- LLM, latent-state, or private Qwen reproduction;
- natural-noise or out-of-distribution robustness;
- adversarial security or writer authentication;
- cross-dataset, cross-language, or cross-domain generalization;
- lower token use, cost, latency, memory, energy, or total resources; or
- autonomous execution authority.
