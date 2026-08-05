# Waggle literature research method

Status: bounded landscape-review method
Review window: 2026-07-10 through 2026-07-11
Paper author: William Keenan
Release note: v0.4 retains this frozen v0.3 literature review unchanged and
adds local hardware/model evidence; it does not extend the search cutoff.

## Purpose

This method supports a publication-candidate landscape review. It is designed
to:

1. separate source-reported results from Waggle evidence;
2. identify direct prior art, counterevidence, safety work, and adjacent work;
3. prevent a bounded search from becoming an absolute novelty claim;
4. pin citations to the revisions used for v0.3.

It is not a systematic review under PRISMA, a meta-analysis, a patent search,
legal advice, or proof of priority.

## Source hierarchy

Technical claims use, in order of preference:

1. the paper or version-of-record page;
2. the authors’ official preprint record;
3. an official project implementation where implementation is the claim.

Business facts use company or program primary sources. Marketing claims from
those pages are attributed to the company and are not treated as independent
technical validation.

Secondary explainers, search snippets, Wikipedia, and press summaries are not
the final support for a technical claim. v0.3 replaced the DisCoCat Wikipedia
link with the original paper and added the primary lambeq paper.

## Search lanes

The review used five query families and backward/forward adjacency from known
papers:

### A. Latent inter-model communication

Query concepts included:

- “latent communication LLM multi-agent”
- “KV cache direct semantic communication models”
- “activation communication language model agents”
- “hidden state inter-agent communication”
- “latent collaboration multi-agent systems”
- “embedding multi-agent debate”

### B. Continuous reasoning and multi-hypothesis claims

Query concepts included:

- “continuous chain of thought superposition”
- “reasoning by superposition continuous thought”
- “illusion of superposition latent reasoning”
- “continuous latent reasoning breadth first search”

### C. Deciphering, safety, and covert capacity

Query concepts included:

- “translate emergent communication neuralese”
- “decode LLM latent representations probe”
- “latent communication attack KV cache”
- “safe latent communication guard”
- “AI agent steganography collusion”

### D. Complex, phase, vector-symbolic, and quantum-adjacent work

Query concepts included:

- “Fourier holographic reduced representation phasor”
- “vector symbolic architecture survey”
- “Kuramoto oscillatory neurons”
- “semantic phase locking language”
- “DisCoCat lambeq quantum NLP”
- “quantum multi-agent reinforcement learning entanglement”

### E. Commercial adjacency

Company and program sources were checked for:

- KV-cache productization and disclosed funding;
- prompt-compression middleware;
- quantum-inspired model compression;
- claimed product scope and release date.

These searches test adjacency only. They do not establish a market for Waggle
or Kea.

## Inclusion and exclusion

Included:

- work that changes the representation transmitted between machine agents or
  models;
- continuous-reasoning work directly relevant to multi-hypothesis claims;
- translation, probing, or identifiability work relevant to Kea;
- security work that tests latent attacks, leakage, or covert channels;
- complex/vector/phase methods that motivate a precisely defined experiment;
- primary commercial sources cited only for dated company facts.

Excluded from direct evidence:

- ordinary prompt compression as proof of latent communication;
- generic observability products as proof of latent deciphering;
- model-weight compression as proof of agent-protocol economics;
- optical compression as a canonical transport;
- quantum-language analogy as evidence for classical efficiency;
- uncited personal anecdotes as general results.

## Claim grading

| Grade | Meaning | Paper treatment |
|---|---|---|
| A | Version-of-record or mature primary result directly supports the scoped statement | May say “the study reports,” with task/model scope |
| B | Primary preprint or official source supports the scoped statement | Label preprint/company source and preserve uncertainty |
| C | Adjacent mechanism or analogy | May motivate an experiment; cannot support an outcome claim |
| D | Internal fixture or proposal | Describe exact artifact and limits; no external generalization |

Counterevidence is never downgraded because it conflicts with the thesis.

## v0.2 source audit disposition

The original 29-entry bibliography was reviewed source by source.

- References 1–8 were retained with current titles, revisions, venues, and
  scoped metrics.
- Reference 9 was retained as an 18-method, single-author preprint survey; its
  existence does not prove global absence of products or decoders.
- Reference 10 was corrected to Zhuokai Zhao and narrowed from universal
  decipherability to identifiability under stated assumptions.
- References 11 and 12 received their actual paper titles and abstract pages.
- Reference 13 was retained as within-network synchronization evidence only.
- The former reference 14 bundled three works. It was split into Plate, Frady
  et al., and Kleyko et al.
- Reference 15 was updated to the complete title and v4’s explicit scale
  limitation.
- References 16–18 were replaced or supplemented with primary arXiv papers;
  the Wikipedia DisCoCat link was removed.
- Reference 19 was retained but narrowed from “message-free coordination” to
  its stated quantum-channel architecture.
- The two works bundled under former reference 20 were split and cited in the
  body as real decoder prior art.
- Former reference 21 is now cited as adjacent representation probing.
- Former reference 22 now uses Tensormesh’s official May 2026 announcement,
  which states $24.5 million total funding.
- References 23 and 24 remain commercial adjacency only.
- Reference 25 was updated to the current title/revision and its limited
  capability finding is preserved.
- Reference 26 no longer supports a claim about production-model
  superposition; it is explicitly a toy-model result.
- Reference 27 now links the Nature AlphaQubit paper.
- Reference 28 remains an attributed company announcement; the paper no
  longer generalizes its method into a multi-year reinforcement-learning
  program.
- Reference 29 now has authors, title, and a primary link, and is paired with
  a direct counterevaluation of optical compression.

The resulting v0.3 bibliography contains 33 separately addressable entries.
Every reference is cited in the paper body.

## Metric verification

Headline numbers were checked against the cited primary abstract or official
record. In particular:

- Cache-to-Cache v2 reports approximately 3.1–5.4% improvement over its text
  communication comparison and an average 2.5× latency speedup.
- Communicating Activations reports up to 27% improvement with less than
  one-quarter of the compute in its tested setups.
- LatentMAS v3 reports 70.8–83.7% fewer output tokens and up to 14.6% higher
  accuracy across its reported suite.
- CIPHER reports 0.5–5.0 percentage-point gains in its experiments.

All remain source-reported maxima or aggregates, not Waggle results.

## Novelty protocol

Allowed statement:

> The dated bounded review did not identify one system combining all of the
> registered Waggle/Kea components.

Disallowed statements:

- “No one has done this.”
- “The decoder does not exist.”
- “First ever.”
- “Unclaimed prior art.”
- Any patentability or freedom-to-operate conclusion.

A public novelty claim requires an updated search, a query/result appendix,
review by a domain expert, and—if legal priority matters—qualified counsel.

## Update procedure

Before each paper release:

1. Reopen every arXiv/official source and record the revision used.
2. Re-run the five search lanes from the previous cutoff date.
3. Add counterevidence and failed replications.
4. Reconcile every numeric statement with `CLAIM-LEDGER.md`.
5. Run `node verify.mjs`.
6. Record the source hash and final artifact hash.

## Limitations

The v0.3 review did not search every scholarly index, non-English publication,
patent database, private implementation, product codebase, or unpublished
system. Several 2026 sources are recent preprints. Commercial pages are
self-reported. The field is moving quickly, and absence from this review is
not evidence of absence.
