import { createFixtureMemoryKea } from "./factory.js";
import { createFixtureMessage } from "./fixtures.js";
import { verifyKeaLedger } from "./ledger.js";
import { verifyManifest } from "./registry.js";
import type { KeaEvaluationCheck, KeaEvaluationReport } from "./types.js";

function deterministicClock() {
  let tick = 2;
  return () => `2026-07-11T00:00:${String(tick++).padStart(2, "0")}.000Z`;
}

function check(
  checks: KeaEvaluationCheck[],
  id: string,
  condition: boolean,
  detail: string
): void {
  checks.push({ id, passed: condition, detail });
}

export function runKeaEvaluation(): KeaEvaluationReport {
  const { service, registry, ledger } = createFixtureMemoryKea({
    clock: deterministicClock(),
    maxUndecodableBytes: 0,
  });
  const checks: KeaEvaluationCheck[] = [];

  const fixture = createFixtureMessage();
  const first = service.ingest(fixture);
  check(
    checks,
    "exact-render",
    first.interpretation.disposition === "verified" &&
      first.interpretation.verification.exactRoundTrip === true,
    "Deterministic fixture reconstructs exactly and renders as verified"
  );
  check(
    checks,
    "no-authority",
    first.interpretation.authorityGranted === false,
    "Interpretation cannot grant or execute authority"
  );

  const beforeDuplicate = ledger.read().length;
  const duplicate = service.ingest(fixture);
  let envelopeCollisionRejected = false;
  try {
    service.ingest({
      ...fixture,
      receiverActorIds: ["agent_fixture_other"],
    });
  } catch {
    envelopeCollisionRejected = true;
  }
  check(
    checks,
    "idempotent-ingest",
    duplicate.duplicate && envelopeCollisionRejected && ledger.read().length === beforeDuplicate,
    "An exact duplicate replays without appending and a reused ID with altered envelope metadata is rejected"
  );

  const correction = service.correct({
    interpretationId: first.interpretation.interpretationId,
    actorId: "human_fixture",
    humanGloss: "Human-qualified fixture interpretation",
    reason: "Exercise append-only correction history",
  });
  const replay = service.replay(fixture.messageId);
  check(
    checks,
    "append-only-correction",
    replay.corrections.length === 1 &&
      replay.corrections[0].correctionId === correction.correctionId &&
      replay.interpretations[0].humanGloss === first.interpretation.humanGloss,
    "Correction appends a new record and does not rewrite the original interpretation"
  );

  const beforeCorrupt = ledger.read().length;
  let corruptRejected = false;
  try {
    service.ingest({
      ...createFixtureMessage({ messageId: "keamsg_corrupt" }),
      payloadHash: "0".repeat(64),
    });
  } catch {
    corruptRejected = true;
  }
  check(
    checks,
    "corruption-rejected",
    corruptRejected && ledger.read().length === beforeCorrupt,
    "Payload hash mismatch is rejected before raw fixture storage"
  );

  const unknown = createFixtureMessage({
    messageId: "keamsg_unknown",
    codecId: "unknown.codec",
    codecVersion: "9.9.9",
  });
  const unknownResult = service.ingest(unknown);
  check(
    checks,
    "unknown-codec-quarantined",
    unknownResult.interpretation.disposition === "rejected" &&
      unknownResult.interpretation.budget.exceeded &&
      unknownResult.interpretation.authorityGranted === false,
    "Unknown codec exceeds the zero-undecodable-byte fixture budget and is rejected"
  );

  let liveRejected = false;
  try {
    service.ingest({
      ...createFixtureMessage({ messageId: "keamsg_live" }),
      fixture: false,
    });
  } catch {
    liveRejected = true;
  }
  check(
    checks,
    "live-traffic-closed",
    liveRejected,
    "Reference service refuses non-fixture traffic"
  );

  const chain = verifyKeaLedger(ledger.read());
  check(checks, "hash-chain", chain.ok, "Every ledger event verifies against its predecessor");
  check(
    checks,
    "registry-integrity",
    registry.list().length === 1 && verifyManifest(registry.list()[0]),
    "Codec and decoder manifest is immutable and content-verified"
  );
  check(
    checks,
    "standalone-replay",
    replay.chainVerified && replay.events.length === 3,
    "Message, interpretation, and correction replay in standalone mode"
  );

  const events = ledger.read();
  return {
    schemaVersion: "1.0.0",
    fixtureOnly: true,
    passed: checks.every((item) => item.passed),
    checks,
    messages: events.filter((event) => event.kind === "message").length,
    interpretations: events.filter((event) => event.kind === "interpretation").length,
    ledgerEvents: events.length,
    generatedAt: "2026-07-11T00:00:30.000Z",
    externalCalls: 0,
    modelCalls: 0,
    authorityEffectsExecuted: 0,
  };
}
