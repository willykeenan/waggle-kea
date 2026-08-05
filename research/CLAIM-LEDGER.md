# Waggle + Kea public claim ledger

Status: release control document

Author: William Keenan

Evidence boundary: public fixtures plus the frozen C15d aggregate

Every public claim must name its evidence class and preserve its limitation.
Ambiguous evidence is reported as a hypothesis or rejected.

| ID | Claim | Class | Evidence or gate | Allowed wording | Disallowed wording |
| --- | --- | --- | --- | --- | --- |
| C01 | The public Waggle codec reconstructs four canonical packets | Public fixture | Deterministic tests and Kea evaluation | “4/4 canonical fixture packets round-tripped exactly.” | “Waggle preserves arbitrary meaning perfectly.” |
| C02 | Kea validates the registered decoder boundary | Public fixture | Ten deterministic evaluation checks plus adversarial tests | “The published Kea harness checks manifests, payload integrity, deterministic decoding, replay, and explicit failures.” | “Kea is production-ready, tamper-proof, or independently verified.” |
| C03 | Decoding never grants authority | Public fixture invariant | `authorityGranted` remains false; tests execute zero effects | “Kea produces an inspectable interpretation, never permission to act.” | Any execution authority inferred from a packet or gloss. |
| C04 | C15d reused one native prefix state across six branches | Bounded local aggregate | `RESULTS-C15D.md` and `data/c15d-summary.json` | “One frozen Qwen3-14B prefix state was restored once into one resident Apple Metal context and reused across six source-separated branches; every informed arm produced exact outputs.” | Hidden chain-of-thought transfer, universal language, or arbitrary-model compatibility. |
| C05 | Resident native reuse crossed one weaker comparator but not two stronger controls | Bounded local aggregate | Frozen cumulative completion curve | “Resident native beat repeated resident full-text reconstruction from branch 3 onward, but did not beat cached-prefix text or cache-warmed fresh-native processes.” | “Native state is faster,” “Waggle uses hardware better overall,” or any general efficiency claim. |
| C06 | Native branch-query handoff bytes were smaller in this run | Bounded local aggregate | 2,307 query bytes, 53,415 repeated full-text prompt bytes, and 279,321,005 retained-state bytes | “The measured branch-query handoff was smaller while retained state and qualification overhead remained material.” | Token, credit, memory, energy, cost, or total-resource savings. |
| C07 | The no-state consumer abstained | Bounded local aggregate | 6/6 no-state abstentions | “The restricted no-state consumer abstained on every frozen task.” | General safety, alignment, or deployment claims. |
| C08 | The public package is not an independent replication package | Publication boundary | Public inventory excludes raw native state and the full execution corpus | “The implementation and aggregate are internally checkable; the central model run is not independently reproducible from this package.” | Third-party verification, public raw-state availability, or independent replication. |

## Update rule

A new headline result, safety claim, capability claim, or performance claim
requires:

1. a new ledger row;
2. a named public artifact or frozen gate;
3. an allowed sentence and the strongest tempting overclaim;
4. a matching change to the machine-readable aggregate when applicable; and
5. a passing research verifier and checksum update.

If those requirements are not met, the claim is removed.
