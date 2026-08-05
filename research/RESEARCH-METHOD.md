# Waggle + Kea public evaluation method

Status: bounded reporting protocol

Author: William Keenan

Scope: the public fixture implementation and the frozen C15d aggregate

## Purpose

This document states how evidence enters the public Waggle + Kea package. It
is a reporting protocol, not a systematic literature review, peer review,
patent search, or independent replication.

The method is designed to keep four questions separate:

1. Does the public packet format reconstruct its deterministic fixtures?
2. Does Kea reject invalid or incompatible messages and remain authority-free?
3. Did model-native state reuse work in the one frozen local experiment?
4. Did that mechanism beat the strongest matched performance controls?

A positive answer to one question never supplies a positive answer to another.

## Evidence classes

| Class | Meaning | Public treatment |
| --- | --- | --- |
| Public fixture | Reproducible from this repository without a model or network | May describe only the tested schema, decoder, and failure behavior |
| Bounded local aggregate | Result from the frozen C15d run, published without raw native state or the full execution corpus | May report exact model, hardware, task count, controls, measurements, and limitations |
| Hypothesis | A falsifiable claim awaiting a registered experiment | Must be written as a future test, never as a result |
| Non-claim | A tempting inference the evidence does not establish | Must remain explicitly rejected |

## Public fixture evaluation

The reference implementation is evaluated with sanitized deterministic
fixtures. A passing run requires:

- exact canonical encode/decode round trips;
- content-hash and byte-count verification;
- a registered codec manifest matching the complete compatibility envelope;
- rejection of unknown codecs, malformed schemas, invalid paths, oversized
  payloads, excessive nesting or collections, and decoder disagreement;
- deterministic replay through the single-writer hash-chained ledger; and
- zero model calls, network calls, or authority effects.

The fixture result establishes implementation behavior only. It does not
establish semantic generalization, production safety, or model performance.

## Frozen C15d comparison

The C15d aggregate covers one Qwen3-14B Q6_K model on one Apple M4 Max Metal
path across six source-separated tasks. The comparison contains five informed
arms and one no-state control:

1. one resident context with a restored native prefix;
2. one resident context with a cached readable-text prefix;
3. one resident context rebuilt from full text for each branch;
4. six warmed fresh processes using native restore;
5. six fresh processes using full text; and
6. a no-state consumer required to abstain.

Every informed arm had to produce exact outputs on all six tasks. All observed
startup, restore, and Kea costs remained in the aggregate. The registered
comparison was cumulative wall time at each branch, with no post-hoc removal of
the first-load order effect.

## Admission rules

The mechanism claim is admitted only if native state restores successfully,
all six outputs are exact, every Kea qualification passes, and replay adds no
model work or authority effect.

A performance claim is admitted only against the specifically named arm and
branch horizon it beats. Failure to beat cached-prefix text or warmed
fresh-native controls rejects any overall-efficiency claim even if a weaker
full-text comparator is crossed.

Smaller branch-query bytes do not establish lower token use, memory, energy,
credits, cost, or end-to-end resource consumption. Retained native state and
qualification overhead must remain visible.

## Threats and falsification

The current aggregate is vulnerable to startup order, OS cache and thermal
effects, a six-task correlated sample, fixture dependence, and one
model/hardware configuration. Raw native state and the full execution corpus
are not public, so the result is internally inspectable but not independently
reproducible.

The next falsifying experiment must counterbalance arm order, publish raw
per-run measurements and exact fixtures, include every startup and Kea cost,
and preregister a repeated-run uncertainty rule. The strongest control remains
resident cached-prefix text. A tie or loss is a valid result.

## Required non-claims

This package does not establish a learned or universal agent language, hidden
chain-of-thought transfer, semantic advantage, cross-model or cross-hardware
generalization, production readiness, independent replication, or token,
credit, cost, memory, energy, or overall-efficiency savings. Kea qualification
never grants execution authority.

## Release procedure

Before a public release:

1. reconcile every result sentence with `CLAIM-LEDGER.md` and
   `data/c15d-summary.json`;
2. run `npm run check`;
3. regenerate `SHA256SUMS` for the public research files;
4. scan the complete public tree and Git history for credentials, private
   paths, private implementation identifiers, and excluded branding; and
5. verify the repository, release, CI, and paper asset while signed out.
