# Security

This repository is a fixture-only research implementation. It must not be used
as an authorization boundary or connected to consequential actions without an
independent security review.

The implementation fails closed on malformed envelopes, payload-integrity
errors, unknown codecs, manifest mismatches, causal gaps, idempotency
collisions, decoder disagreement, oversized HTTP bodies, and ledger-chain
tampering. Message and interpretation records are committed as one guarded
batch, and the HTTP service is read-only unless fixture writes are explicitly
enabled.

These controls do not authenticate a permitted writer. SHA-256 identity and a
local hash chain can detect changed content under the verifier, but they are
not signatures, an external timestamp authority, a replicated consensus log,
or proof of benign intent. The included rehashed-forgery control documents this
boundary. Kea qualification never grants execution authority.

Please report suspected vulnerabilities privately through GitHub's security
advisory workflow for this repository. Do not include credentials, personal
data, or private production payloads in a public issue.
