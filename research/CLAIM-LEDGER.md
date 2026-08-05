# Waggle v0.4 claim ledger

Status: public-research-release control document
Author: William Keenan
Date: 2026-07-27

Every material claim in the paper must fit one of four classes:

- **External evidence** — a cited source reports the result in a stated scope.
- **Fixture evidence** — deterministic local evidence exists, with explicit
  limitations.
- **Hypothesis** — a falsifiable mechanism or commercial proposition awaiting
  a registered experiment.
- **Non-claim** — language the project explicitly refuses to assert.

External source results must be attributed to their authors. “Reported,” “in
the tested setup,” and “up to” are part of the claim when the source uses
them. No source result becomes a Waggle result by citation.

| ID | Claim | Class | Evidence or gate | Allowed wording | Disallowed wording |
|---|---|---|---|---|---|
| C01 | Direct machine transports can outperform prose in some experiments | External evidence | References 4–8 | “Prior work reports gains on selected models and benchmarks.” | “Latent communication is always faster or better.” |
| C02 | Latent compatibility is narrow | External evidence / architecture | References 5, 7–9; declared compatibility domains | “A codec is valid only for registered models, layers, adapters, and decoders.” | “All models share a universal latent language.” |
| C03 | Continuous representations can retain multiple alternatives in some settings | External evidence, contested | References 1–3 | “Specific constructions show parallel search; common fine-tuning regimes may collapse it.” | “A vector naturally contains many complete thoughts.” |
| C04 | Machine communication can be translated or probed | External evidence | References 10, 22–24 | “Prior work makes machine-message interpretation measurable under stated assumptions.” | “Kea is provably able to read any hidden state.” |
| C05 | The integrated Waggle/Kea assembly was not found in the bounded review | Bounded search result | `RESEARCH-METHOD.md` | “The dated review did not identify one system combining all registered components.” | “No one has done this,” “first ever,” or a patent-priority claim. |
| C06 | Kea fixture alpha passed 10 deterministic checks | Fixture evidence | Companion fixture evidence dated 2026-07-11 | “10/10 local fixture checks were recorded.” | “Kea is production ready, secure, independently verified, or immutable.” |
| C07 | Waggle v0 reconstructed four packets exactly | Fixture evidence | Companion fixture evidence | “4/4 canonical fixture packets round-tripped.” | “Waggle preserves arbitrary meaning perfectly.” |
| C08 | The fixture byte proxy was smaller than a repeated-context prose baseline | Fixture evidence | Repeated-context fixture | “One simple fixture used fewer encoded bytes than a deliberately weak prose baseline that restated context.” | Token, cost, latency, memory, or production savings. |
| C09 | Current Kea gaps are known | Fixture evidence / limitation | Source inspection | “Registry signing, separately implemented decoding, entitlement export, statistical watch, and external anchoring remain unbuilt.” | “Complete observability product.” |
| C10 | v0 may reduce coordination cost | Hypothesis | E1 + v0 E2 | “v0 will be compared with a reference-optimized prose baseline.” | Any savings claim before matched quality and total-cost evidence. |
| C11 | Learned vectors may preserve useful alternatives | Hypothesis | E2, E3, E5 | “v1 is an unbuilt, killable experiment.” | “Agents communicate in superposition today.” |
| C12 | Phase composition may improve consensus | Hypothesis | E4, E5 | “Registered phase coherence will be tested against debate and aggregation.” | “Agreement is a physical property of the channel” or “interference proves truth.” |
| C13 | Classical shared state may reduce retransmission | Hypothesis | E6 | “Versioned shared state may reduce repeated bytes.” | “Entanglement,” “telepathy,” or correlation without communication. |
| C14 | Latent channels introduce attack and leakage risk | External evidence | References 11, 12, 28 | “Attacks and reconstruction leakage have been demonstrated in research settings.” | “Kea makes latent communication safe.” |
| C15 | v0 may be easier to validate than unconstrained chat | Hypothesis | E5 applied to v0 and prose controls | “Constrained schemas reduce some degrees of freedom but retain covert channels.” | “v0 has almost no hiding capacity” or “prose is unauditable.” |
| C16 | Kea cannot grant authority | Fixture invariant / architecture | Deterministic capability envelope and governor contract | “Only the governed execution envelope may authorize an action.” | Any side effect caused by a payload or gloss. |
| C17 | Quantum ideas are analogies and optional research | Non-claim | References 18–21, 30–31 | “Category theory and quantum systems motivate questions about composition and measurement.” | Quantum computation, speedup, entanglement, or “already quantum-compilable.” |
| C18 | Optical context compression is adjacent and contested | External evidence | References 32–33 | “Rendering text as images can compress tokens, but direct encoders match or beat the detour in a later evaluation.” | “Images are a canonical machine memory format.” |
| C19 | Adjacent companies have received funding | External business evidence | Official references 25–27 | Exact attributed figures and dates only | “The market validates Waggle/Kea” or inferred valuation/demand. |
| C20 | Kea could be independently useful | Commercial hypothesis | Future customer discovery and production evidence | “Kea’s observability and replay surface is a product hypothesis.” | Customer demand, pricing, revenue, savings, or adoption today. |
| C21 | Current approved external spend is zero | Governance fact | Current workstream boundary | “No external spend is approved for this candidate.” | Future compute price or total program budget. |
| C22 | The paper is authored by William Keenan | Authorship metadata | Repository history and CFF metadata | “William Keenan.” | ORCID, affiliation credential, degree, institutional appointment, or contact address not supplied and verified by the author. |
| C23 | C14a exercised classical phase composition on a real Apple GPU | Bounded local hardware evidence | Accepted C14a freeze, Metal device receipt, CPU Kea recomputation, matched controls | “A real Apple M4 Max Metal kernel composed 15 source-separated parent states across six frozen numeric scenarios; CPU-side Kea separately recomputed every component.” | Qubits, entanglement, quantum superposition, quantum speedup, learned language, semantic advantage, or faster-than-CPU claims. |
| C24 | C15d reused one model-native prefix state across six branches | Bounded local model/hardware evidence | `RESULTS-C15D.md`, frozen five-arm comparison, restart replay | “One frozen Qwen3-14B native prefix was restored once into one resident context and reused across six source-separated branches; Kea separately qualified every result.” | Hidden chain-of-thought transfer, a universal latent language, production portability, or arbitrary-model compatibility. |
| C25 | Resident-native reuse has one bounded latency advantage and two stronger negative controls | Bounded local performance evidence | Frozen completion curve in `RESULTS-C15D.md` | “Resident native beat repeated resident full-text reconstruction from branch 3 onward in this six-branch run, but did not beat cached-prefix text or cache-warmed fresh-native processes.” | “Waggle uses the hardware better overall,” “native state is faster,” or removal of the observed startup/order cost after the result. |
| C26 | Native branch queries used fewer handoff bytes than repeated full-text prompts | Bounded representation measurement | `2,307` native query bytes versus `53,415` repeated full-text prompt bytes; retained state `279,321,005` bytes | “The measured branch-query handoff was smaller, while retained native-state and verification overhead remained material.” | Token savings, credit savings, memory savings, energy savings, total-cost savings, or overall encoding advantage. |
| C27 | The public package contains a deterministic reference implementation and aggregate evidence, not the native execution corpus | Publication fact / limitation | Public repository inventory and offline verifier | “The code and aggregate are internally checkable and content-addressed; raw native state and the full experiment implementation remain private.” | Independent replication, public raw-state availability, or third-party verification. |

## Update rule

A new headline number, “first” statement, safety claim, capability claim, or
commercial claim requires:

1. a new ledger row;
2. a source or named evidence artifact;
3. scope and counterevidence;
4. allowed and disallowed wording;
5. a paper-version increment if public meaning changes.

If the evidence is ambiguous, the claim is a hypothesis or is removed.
