# Waggle and Kea: A Bounded Evaluation of Native-State Reuse for Machine-Agent Coordination

William Keenan

August 2026

## Abstract

Machine agents typically coordinate through natural-language messages that are
easy to inspect but can repeatedly transmit context and blur the boundary
between description and authorization. Waggle is an experimental protocol for
typed, content-addressed coordination deltas. Kea is a separate decoder and
audit layer that registers codec manifests, reconstructs messages, records
hash-chained interpretations, exposes uncertainty, and never grants authority
to act. This paper presents an open-source, fixture-only TypeScript reference
implementation and two bounded evaluations. Canonical fixture packets
round-tripped exactly under deterministic decoding. In a separate six-branch
local study, reuse of one Qwen3-14B native prefix state preserved exact outputs
and outperformed repeated full-text reconstruction after branch two, but did
not outperform cached-prefix text or warmed fresh-native controls. The
overall-efficiency hypothesis was therefore rejected. The contribution is a
falsifiable coordination and audit design with explicit failure states—not a
claim of a universal latent language, token savings, or production readiness.

## 1. Research question

On one frozen Qwen3-14B state executed on an Apple M4 Max, can native prefix
state be restored once and reused across six source-separated task branches
while preserving exact outputs under Kea qualification, and how does its
measured branch latency compare with matched full-text and cached-prefix
controls?

This question separates four properties that are often conflated:

1. representation size;
2. reconstruction fidelity;
3. task behavior;
4. permission to execute a consequential action.

Waggle addresses representation and composition. Kea measures reconstruction,
records uncertainty, and enforces an architectural invariant:
`authorityGranted` is always false.

## 2. System design

Waggle v0 packets contain a protocol version, message class, intent, symbolic
operation, content-addressed references, and a typed state delta. Runtime
validation rejects missing fields, unregistered enums, prose-bearing fields,
invalid tokens, excessive nesting, excessive collections, and oversized
payloads. Canonical JSON and SHA-256 provide deterministic content identity.

Kea registers an integrity-checked codec manifest and a matching decoder. It
verifies the payload hash and byte count before decoding, checks the complete
codec envelope against the manifest, reconstructs deterministic payloads, and
records the raw message and interpretation in a single-writer hash chain.
Unknown codecs, unavailable decoders, manifest mismatches, oversized payloads,
out-of-distribution values, and decoder disagreement fail closed.

The implementation is fixture-only. It performs no model calls, network calls,
or authority effects.

## 3. Evaluation method

The public reference implementation uses deterministic fixtures and adversarial
boundary tests. The broader research method freezes claim wording, matched
controls, stopping rules, and disallowed inferences before public reporting.

The bounded C15d study compared five equally informed arms across six tasks:

- one resident context with a restored native prefix;
- one resident context with a cached readable-text prefix;
- one resident context rebuilt from full text for each branch;
- six warmed fresh processes using native restore;
- six fresh processes using full text.

A no-state consumer served as an abstention control. Exact byte and semantic
parity were required for every informed arm. Startup order and all observed
costs remained in the result.

## 4. Results

The deterministic fixture evaluation recorded exact reconstruction for four
canonical packets and a passing local audit harness. These results demonstrate
only the published schema and decoder behavior.

In the six-branch C15d study, every informed arm produced exact outputs on all
six tasks, while the no-state consumer abstained on all six. Resident-native
reuse became faster than repeated resident full-text reconstruction from branch
three onward. It remained slower than cached-prefix text and the warmed
fresh-native control at the end of the frozen evaluation.

The mechanism result was admitted: native prefix state was restored and reused
with exact outputs. The broader efficiency result was rejected: the strongest
controls were faster, retained state was large, and model-load order was not
counterbalanced.

## 5. Threats to validity

The model/hardware study is one local, six-task run on an Apple M4 Max using a
quantized Qwen3-14B model. OS cache and thermal state were not controlled, and
the first model load showed a large order effect. The public aggregate does not
include raw native state or the complete execution corpus. No conclusion should
be generalized to other models, hardware, tasks, providers, or production
systems.

The reference packet format also constrains visible prose fields; it does not
eliminate covert channels or prove semantic safety. Hash chaining detects
retrospective modification under the verifier but is not a signature,
timestamp authority, or tamper-proof external log.

## 6. Explicit non-claims

This work does not establish:

- a universal or learned AI-to-AI language;
- access to hidden chain-of-thought;
- token, credit, latency, memory, energy, or total-cost savings;
- arbitrary cross-model compatibility;
- security under adversarial production traffic;
- production readiness or autonomous execution;
- quantum computation, entanglement, or quantum speedup.

## 7. Next experiment

The next falsifying experiment should counterbalance startup and cache order,
extend the branch horizon, preserve matched context and exact-output gates, and
include Kea overhead in every arm. The hypothesis survives only if the resident
native arm crosses the strongest cached-prefix control under the frozen rule.
A tie or negative result is valid.

## 8. Availability

The TypeScript reference implementation, deterministic fixtures, tests, claim
ledger, research method, and aggregate result are available in this repository
under MIT and CC BY 4.0 licenses. The release is authored by William Keenan and
has not undergone peer review.
