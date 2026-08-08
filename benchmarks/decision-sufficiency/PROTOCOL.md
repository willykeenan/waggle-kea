# Certified task-sufficient prediction handoffs

Status: preregistered prospective secondary analysis; no result observed

Author: William Keenan

## Research question

For a frozen multiclass prediction vector and a frozen downstream expected-cost
policy, how many probability components must one machine disclose before a
separate consumer can **prove** that every completion of the omitted mass leads
to the same bounded action as the complete vector?

The question is decision sufficiency, not generic compression. A smaller
message is useful only when it preserves the full-vector decision exactly. If
the omitted mass can change that decision, the consumer must receive more
components or return `insufficient_confidence`.

## Scientific alternatives considered

Three successor designs were considered before implementation:

1. another intent-classifier architecture comparison;
2. another native-KV versus cached-text timing run; and
3. a decision-sufficiency experiment with a mathematical refusal certificate.

The first was rejected because character n-grams and intent classification are
well-established and the existing public result is already exploratory. The
second was rejected because the private C17b line ended with exact
representation parity but a failed task-quality gate. The third is selected
because it tests a distinct, falsifiable interface property and can be
reproduced without proprietary model state.

## Evidence status

The classifier and BANKING77 population were evaluated in v0.2.0, so this is
not an independent model replication and does not become one merely because
the new analysis is frozen. The estimand, policies, certificate algorithm,
controls, thresholds, implementation, and tests are frozen before any new
full-vector or decision-sufficiency output is generated. The correct label is
therefore **preregistered prospective secondary analysis of a previously
evaluated model and population**.

## Frozen prediction state

The source, filtering, word-plus-character TF-IDF representation,
`SGDClassifier`, seed, and public train-disjoint test population are inherited
unchanged from `benchmarks/banking77/`. The new runner fits only the canonical
candidate model and converts each 77-class probability vector to integer parts
per million using deterministic largest-remainder quantization. Every vector
must contain exactly 77 non-negative integers summing to 1,000,000. Source text
is excluded from all committed prediction-state artifacts.

The full-vector action is the unique minimum expected-cost action under that
integer vector. Exact ties return `insufficient_confidence`.

## Frozen policy family

Twelve policies each contain four actions. For every policy, each of the 77
intent labels is assigned to one action by SHA-256 of the public policy seed
and label. Choosing the assigned action has cost 0; every other action has cost
1,000. The mapping is deterministic, label-blind, generated without prediction
outputs, and must give every action at least one label. These are synthetic
decision geometries, not a claim about real bank operations.

The multi-policy design prevents one hand-authored meaning codebook from
manufacturing the result. Case is the resampling unit; policy decisions from
the same case are not treated as independent observations.

## Certificate and proof rule

The producer reveals probability components in descending order. At each
prefix, for candidate action `a` and every opponent `b`, it computes the exact
known expected-cost advantage of `a` over `b`. All omitted probability mass is
then assigned to the omitted label that is worst for that pair. Action `a` is
certified only when the lower bound remains strictly positive against every
opponent.

This is a robust interval statement: every non-negative allocation of the
omitted mass consistent with the declared total must preserve the action. The
certificate contains integer inputs and pairwise lower bounds, so Kea and the
restricted consumer can recompute the proof without floating-point tolerance.
Kea additionally receives the frozen full vector, verifies its content ID,
reconstructs the canonical minimal-prefix certificate, and compares against
the full-vector action. The restricted consumer never receives the full vector,
source text, true label, expected action, or model.

At most eight of 77 probabilities may be revealed. Failure to certify within
that budget returns `insufficient_confidence`; it never falls back to the
nominal top class.

### Exact theorem used by the certificate

Let `C[a,i]` be the frozen integer cost of action `a` at label `i`, let `R` be
the revealed indices, let `O` be the omitted indices, and let `r` be the exact
omitted probability mass. For candidate `a` and opponent `b`, define

`L(a,b) = sum(i in R) p[i] * (C[b,i] - C[a,i]) + r * min(i in O)(C[b,i] - C[a,i])`.

The omitted contribution is linear over a simplex, so its minimum is attained
by placing all omitted mass on an omitted label with minimum cost difference.
Therefore `L(a,b)` is the exact worst-case value of `cost(b)-cost(a)` over all
completions. A fixed candidate `a` is the unique minimum-cost action for every
completion if and only if `L(a,b) > 0` for every opponent `b`. The strict
inequality rejects ties.

The implementation reveals components in the frozen descending-probability
order and returns the **first certifying prefix** in that chain. It does not
claim the globally smallest subset, the shortest possible encoding, or a
minimum universal message.

## Matched controls

Every case-policy pair is evaluated with identical prediction information and
policy:

1. full 77-class vector;
2. adaptive robust certificate with at most 8 revealed probabilities;
3. fixed safe certificate with at most 1 probability;
4. fixed safe certificate with at most 3 probabilities;
5. naive top-1 action with no residual-mass proof; and
6. a content-addressed four-action expected-cost summary, computed from the
   complete vector and independently checked by the frozen verifier; and
7. no-state, required to abstain.

The expected-cost summary is the strongest compact informed control for this
policy family. It is allowed to tie or beat the certificate in bytes and
decision utility. Unlike the partial certificate, it does not expose a proof
that is valid under every completion of omitted probability mass; it relies on
Kea's prior full-vector check. Its presence prevents a smaller-message result
from being mislabeled as a unique encoding or compression advantage.

The full-vector arm is serialized to canonical JSON, decoded in a separate
round-trip step, content-addressed again, and then scored. A self-comparison of
one in-memory reference object does not count as reconstruction evidence.

Canonical JSON and Waggle/Kea carry the same certificate semantics. Payload,
envelope, qualification, and ledger bytes are reported separately. A compact
state does not establish an encoding advantage if the complete Waggle/Kea
artifact is larger than canonical JSON.

## Primary hypothesis and decision rule

`H1_TASK_SUFFICIENCY_SUPPORTED` is admitted only if all frozen conditions hold:

- the adaptive certificate safely continues at least 90% of full-vector
  non-tied case-policy decisions;
- its safe coverage exceeds safe `k=1` coverage by at least 10 percentage
  points;
- every adaptive continuation matches the full-vector action;
- the canonical full-vector round trip has zero ID or decision mismatch;
- the verified expected-cost summary has zero decision mismatch;
- naive top-1 differs from the full-vector action at least once, demonstrating
  that a label alone is not generally sufficient;
- no-state continues zero times;
- Kea and the restricted consumer reject every specified tamper and grant no
  authority; and
- all provider, model-API, and authority-effect counts remain zero.

Otherwise the result is `H0_RETAINED`. A negative result is valid and must not
be repaired by changing policies, budgets, thresholds, cases, or denominators.

Secondary quantities include safe coverage at every `k` from 1 through 8,
revealed-component distributions, case-clustered bootstrap intervals,
per-policy coverage, full-state, certificate, and expected-cost-summary bytes,
Waggle/Kea overhead, model accuracy and macro-F1 for continuity only, and exact
refusal counts. They are committed to `evaluation.json` and independently
recomputed; stdout is not durable evidence. They cannot replace a failed
primary gate.

## Falsification and attacks

The evaluation must reject altered probability mass, reordered or duplicate
indices, a forged residual, action or bound changes, policy drift, vector-ID
drift, rehashed certificate or qualification changes, unknown fields,
non-integer/non-finite/negative values, extra files, symlinks, replay changes,
and authority smuggling. A source writer with permission to replace both the
vector and its hash remains outside content-hash authentication and is stated
as a limitation.

## Literature boundary

The experiment is informed by information-bottleneck work on bounded multi-
agent relays, decision-sufficient representations, selective classification,
minimum-necessary agent disclosure, and same-decision probability. It does not
claim to invent any of those fields. Same-decision probability asks for a
probability that a partially observed system selects the same decision; this
experiment instead gives a deterministic all-completions certificate under a
frozen cost policy. Its narrower contribution is an inspectable, integer-exact
decision certificate with an independent Kea verifier and a source-separated
consumer on one public multiclass workload.

- Ye, Amin, and Özdağlar (2026), “Learning Decision-Sufficient
  Representations for Linear Optimization,” COLT.
- Yu et al. (2026), “When Do Multi-Agent Systems Help? An Information
  Bottleneck Perspective,” arXiv:2607.16133.
- Xu et al. (2026), “MNC: Scope-Bound Semantic Declassification for Private
  LLM-Agent Communication,” arXiv:2608.01719.
- Cattelan and Silva (2024), “How to Fix a Broken Confidence Estimator,” UAI.
- Chen, Choi, and Darwiche (2014), “Algorithms and Applications for the
  Same-Decision Probability,” JAIR.

## Non-claims

This experiment cannot establish a minimum universal message, semantic
compression, hidden-state transfer, learned language, neuralese, privacy,
security against authenticated malicious writers, cross-dataset or cross-model
generalization, production readiness, token/credit/cost/energy savings,
overall efficiency, autonomous authority, or quantum behavior.
