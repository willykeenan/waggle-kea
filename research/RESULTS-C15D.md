# C15d-G1: Amortized model-native context service

- Author: William Keenan
- Research context: independent
- Release date: 2026-07-27
- Evidence class: bounded local model and hardware experiment
- Peer review: none

## Research question

Can Waggle preserve one model-native prefix state, restore it once into a
resident local context, serve multiple source-separated branches without
reconstructing intermediate prose, and pass every result through separate
Kea qualification—while outperforming equally informed context controls?

## Verdict

The mechanism worked. The overall-efficiency claim did not.

A frozen Qwen3-14B native prefix state was restored once into one resident
context on an Apple M4 Max Metal path and reused across six branches. Kea
separately qualified every output and bound the restricted projection to a
separately pinned trust root. A fresh consumer that received only the
Kea-qualified projection continued; a no-state consumer abstained.

All five informed arms produced exact outputs on all six tasks. Resident-native
reuse beat repeated resident full-text reconstruction from branch 3 through
branch 6. It did not beat the resident cached-prefix text control or the six
cache-warmed fresh-native processes during this frozen evaluation.

## Frozen comparison

| Arm | Model process loads | Prefix strategy | Exact tasks |
|---|---:|---|---:|
| Resident native | 1 | Restore native state once; reuse one context | 6/6 |
| Resident cached text | 1 | Prefill readable prefix once; reuse one context | 6/6 |
| Resident full text | 1 | Rebuild context and full prompt per branch | 6/6 |
| Fresh native | 6 | New process and native restore per branch | 6/6 |
| Fresh full text | 6 | New process and full prompt per branch | 6/6 |
| No state | 0 | No projection | 0/6; abstained |

Every informed arm used 1,781 input tokens per task and produced exact byte and
semantic parity. Every output had `authorityGranted=false`.

## Completion curve

Times are milliseconds. Fresh-process values are cumulative.

| Branches | Resident native | Cached-prefix text | Resident full text | Fresh native | Fresh full text |
|---:|---:|---:|---:|---:|---:|
| 1 | 13,779.464 | 6,496.367 | 6,339.878 | 2,724.858 | 6,358.122 |
| 2 | 14,986.787 | 7,719.157 | 12,221.532 | 5,292.213 | 12,571.268 |
| 3 | 16,184.914 | 8,923.273 | 18,110.261 | 7,924.609 | 18,844.386 |
| 4 | 17,247.436 | 10,003.464 | 23,861.429 | 10,373.340 | 24,863.371 |
| 5 | 18,442.572 | 11,202.696 | 29,750.828 | 12,920.081 | 31,040.636 |
| 6 | 19,848.887 | 12,606.107 | 35,837.325 | 15,650.045 | 37,402.632 |

The preregistered break-even rule required the first strict advantage that
persisted through branch 6:

- versus resident full text: branch 3;
- versus cached-prefix text: no crossing;
- versus fresh native: no crossing.

End-to-end process wall was 20,285.204 ms for resident native, 12,850.184 ms
for cached-prefix text, 36,140.624 ms for resident full text, 17,881.462 ms for
fresh native, and 39,570.007 ms for fresh full text.

## Hardware and resource facts

- Device: Apple M4 Max, Metal, unified memory/shared buffers, no CPU fallback.
- Local model: Qwen3-14B Q6_K.
- Frozen prefix: 1,701 tokens.
- Native state retained: 279,321,005 bytes.
- Native state read: 1,019.981 ms.
- Native state restore: 62.562 ms.
- Cached-text shared-prefix prefill: 4,174.607 ms.
- Native branch-query bytes: 2,307.
- Repeated full-text prompt bytes: 53,415.
- Maximum process peak RSS: 2,023,538,688 bytes.
- Kea plus restricted-consumer overhead: 5,586.970 ms.
- Total evaluation wall: 132,314.449 ms.
- Direct energy measurement: unavailable; no TDP estimate was substituted.

The smaller branch handoff and faster native restore do not establish total
token, credit, memory, energy, or overall-efficiency savings. The retained
state was large and the strongest informed control was faster.

## Order-effect limitation

Process order was frozen before task outputs: resident native ran first,
followed by cached text, resident full text, and alternating fresh-native and
fresh-text pairs. The first resident-native model load took 10,949.390 ms,
while the later cached-text load took 369.289 ms and all six fresh-native
loads totaled 2,013.880 ms.

OS cache and thermal state were not controlled. This is an observed order
effect, not a causal explanation and not permission to remove startup cost
after observing the result. A counterbalanced warm-start, longer-horizon
experiment is required before an overall hardware-utilization claim.

## Integrity and verification

- Implementation/test freeze pins: 23.
- Accepted local model process loads: 15 of an authorized maximum 16.
- Accepted forward/decode steps: 690 of an authorized maximum 2,048.
- Hash-chained ledger steps: 9.
- Restart replay: zero additional model work.
- Adversarial attacks rejected: 13, including a fully rehashed forged-lineage
  projection rejected against a separate trust root.
- Focused suite, formal replay, prior-checkpoint replay, typecheck, build, and
  cold CLI inspection: passed.
- Provider/API model calls: 0.
- External calls: 0.
- Training runs: 0.
- Deployments during the experiment: 0.
- Authority effects executed: 0.
- Authority granted: false.

Provenance:

- Sanitized source evidence SHA-256:
  `2daa72b763509459321ed81bafb4a0cd5f5b835a409e65de5606f1f522b60c10`
- Evaluation SHA-256:
  `1880d3b47c545538090cdd4dc0d4fbdde784240e569660197f7dc5932d68cb19`
- Report SHA-256:
  `6ff978727606f189e09c14e3b833107e7c6f2e0c75865692e5e617e16ffd7c18`

The raw native state and full experiment implementation are not part of this
public release. These hashes bind this summary to retained evidence but do not
constitute independent replication, authorship signatures, or public
reproducibility.

## Admitted and rejected claims

Admitted:

> For six frozen local fixtures, Waggle reused one Qwen3-14B native prefix
> state on Apple Metal across multiple branches, Kea separately qualified
> each handoff, and the resident-native arm beat repeated resident full-text
> reconstruction from branch 3 onward.

Rejected:

- better overall hardware utilization;
- unique capability or semantic-quality advantage;
- token, credit, memory, energy, or total-cost savings;
- a learned or emergent AI-to-AI language;
- hidden chain-of-thought transfer;
- qubits, entanglement, quantum superposition, or quantum speedup;
- production readiness, deployment safety, or authority.

## Next falsifiable experiment

Counterbalance startup and cache order before outputs are observed, extend the
branch horizon, and test whether a resident native service ever crosses the
strongest cached-prefix control while preserving exact quality and full Kea
overhead. A tie or negative result is valid.
