# BANKING77 client-intent and audited-handoff benchmark

This reproducible benchmark adds a real public machine-learning task to
Waggle + Kea. It trains matched classical intent classifiers on the official
BANKING77 split, evaluates a leakage-controlled test population, and then
passes the frozen predictions through direct, JSON, and Waggle/Kea handoffs.

The committed reference run is exploratory. Read [`PROTOCOL.md`](PROTOCOL.md)
before interpreting its metrics.

## Committed reference result

The leakage-controlled primary test contains 3,050 unique, unambiguous queries
that do not occur in normalized training text.

| Model | Accuracy | Macro-F1 | Top-3 accuracy | Log loss | ECE |
| --- | ---: | ---: | ---: | ---: | ---: |
| Word TF-IDF + SGD | 0.8915 | 0.8915 | 0.9708 | 0.5848 | 0.2106 |
| Word + character TF-IDF + matched SGD | 0.9115 | 0.9119 | 0.9744 | 0.4434 | 0.1467 |

The exploratory paired macro-F1 difference is **+0.0203**, with a 2,000-draw
label-stratified paired bootstrap interval of **[+0.0140, +0.0274]**. The
label-shuffled control scored 0.0095 macro-F1. Under the deterministic
single-character-deletion stress, macro-F1 was 0.7728 for the word-only model
and 0.8565 for the word-plus-character model; this is synthetic sensitivity,
not natural-noise validation.

All 3,050 frozen predictions retained exact routes through direct, canonical
JSON, and Waggle/Kea handoffs. The 64-case content-addressed fault sample
recorded zero false accepts across six specified detectable fault families,
zero clean rejections, and zero authority grants. A fully rehashed permitted-
writer forgery remained undetected as expected; content hashes do not
authenticate writer intent.

## Reproduce

From the repository root:

```bash
python3 -m venv benchmarks/banking77/.venv
benchmarks/banking77/.venv/bin/python -m pip install -r benchmarks/banking77/requirements.lock
benchmarks/banking77/.venv/bin/python benchmarks/banking77/run.py
npx tsx benchmarks/banking77/handoff.ts
node scripts/verify-banking77-benchmark.mjs --results benchmarks/banking77/results/local-v1
npx tsx --test tests/banking77-benchmark.test.ts
```

The first run downloads three files from the pinned official GitHub commit
into `benchmarks/banking77/.cache/source/`. Later runs use the verified cache.
Pass `--offline` to `run.py` to forbid acquisition and require the cache.

Normal reproduction writes to the ignored `results/local-v1/` directory, so
timestamps and environment paths do not dirty the repository. The committed
reference was generated only with an explicit `--output
benchmarks/banking77/results/reference-v1` argument. Running the verifier with
no `--results` argument always checks that committed reference independently.

## Outputs

The reference package under `results/reference-v1/` contains:

- `run.json`: configuration, source provenance, data audit, model metrics,
  uncertainty, stress results, controls, verdict, and non-claims;
- `predictions.jsonl`: one content-addressed, text-free record per primary test
  case;
- `per-intent.json`: complete per-class metrics for the matched classifiers;
- `environment.json`: runtime and dependency facts;
- `handoff.json`: complete routing/authority results plus a bounded,
  content-addressed idempotency/corruption/ledger fault sample; and
- `SHA256SUMS`: integrity hashes for every result artifact.

The verifier treats both `H1_SUPPORTED_EXPLORATORY` and `H0_RETAINED` as valid
scientific outcomes. It fails only when the evidence contract is broken.
