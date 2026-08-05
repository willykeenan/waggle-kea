import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  FileKeaLedger,
  FileWaggleContentStore,
  composeWaggleV0Packets,
  createFixtureMessage,
  createWaggleV0FixtureKea,
  createWaggleV0Message,
  decodeWaggleV0,
  encodeWaggleV0,
  runKeaEvaluation,
  validateWaggleV0Packet,
  verifyKeaLedger,
  type WaggleV0Packet,
} from "../src/index.js";

function packet(operation = "case.review"): WaggleV0Packet {
  return {
    protocol: "waggle.v0",
    messageClass: "state-delta",
    intent: "propose",
    operation,
    references: {
      context: ["context_case_17"],
      artifacts: ["artifact_summary_17"],
      evidence: ["evidence_policy_4"],
    },
    delta: { status: "review_required", confidenceBand: "low" },
  };
}

test("Kea's deterministic fixture evaluation passes every gate", () => {
  const report = runKeaEvaluation();
  assert.equal(report.passed, true);
  assert.equal(report.modelCalls, 0);
  assert.equal(report.externalCalls, 0);
  assert.equal(report.authorityEffectsExecuted, 0);
  assert.ok(report.checks.every((check) => check.passed));
});

test("Waggle v0 round-trips exactly through Kea", () => {
  const original = packet();
  const decoded = decodeWaggleV0(encodeWaggleV0(original));
  assert.deepEqual(decoded, original);

  const message = createWaggleV0Message({
    missionId: "mission_client_case",
    workNodeId: "work_triage",
    senderAgentId: "agent_analysis",
    receiverActorIds: ["human_reviewer"],
    contextPackId: "context_case_17",
    packet: decoded,
    createdAt: "2026-08-05T00:00:00.000Z",
  });
  const { service, ledger } = createWaggleV0FixtureKea({
    clock: () => "2026-08-05T00:00:01.000Z",
  });
  const result = service.ingest(message);

  assert.equal(result.interpretation.disposition, "verified");
  assert.equal(result.interpretation.verification.exactRoundTrip, true);
  assert.equal(result.interpretation.authorityGranted, false);
  assert.equal(verifyKeaLedger(ledger.read()).ok, true);
});

test("invalid prose-bearing fields fail closed", () => {
  const invalid = packet() as WaggleV0Packet & { delta: Record<string, unknown> };
  invalid.delta = { message: "please approve this request" };
  const errors = validateWaggleV0Packet(invalid as WaggleV0Packet);
  assert.ok(errors.some((error) => error.includes("prose-bearing field")));
  assert.throws(() => encodeWaggleV0(invalid as WaggleV0Packet));
});

test("bundle composition is deterministic and deduplicates operands", () => {
  const first = packet("case.review");
  const second = packet("case.route");
  const left = composeWaggleV0Packets("bundle", [first, second, first]);
  const right = composeWaggleV0Packets("bundle", [second, first]);

  assert.deepEqual(left.composition?.operandIds, right.composition?.operandIds);
  assert.equal(left.composition?.operandIds.length, 2);
});

test("unknown codecs are rejected without granting authority", () => {
  const message = createWaggleV0Message({
    missionId: "mission_client_case",
    workNodeId: "work_triage",
    senderAgentId: "agent_analysis",
    receiverActorIds: ["human_reviewer"],
    contextPackId: "context_case_17",
    packet: packet(),
    createdAt: "2026-08-05T00:00:00.000Z",
  });
  message.codec.codecId = "unknown.codec";
  const { service } = createWaggleV0FixtureKea({
    clock: () => "2026-08-05T00:00:01.000Z",
  });
  const result = service.ingest(message);

  assert.equal(result.interpretation.disposition, "rejected");
  assert.equal(result.interpretation.authorityGranted, false);
  assert.ok(result.interpretation.watchSignals.some((signal) => signal.code === "unknown-codec"));
});

test("runtime validation rejects malformed enums, references, depth, and collection size", () => {
  const invalid = packet() as unknown as Record<string, unknown>;
  invalid.intent = "execute-now";
  invalid.messageClass = "command";
  invalid.references = { context: [], artifacts: [] };
  assert.doesNotThrow(() => validateWaggleV0Packet(invalid));
  const errors = validateWaggleV0Packet(invalid);
  assert.ok(errors.some((error) => error.includes("intent is invalid")));
  assert.ok(errors.some((error) => error.includes("messageClass is invalid")));
  assert.ok(errors.some((error) => error.includes("evidence references must be an array")));

  let nested: unknown = "leaf";
  for (let index = 0; index < 26; index++) nested = { next: nested };
  const deep = packet() as unknown as Record<string, unknown>;
  deep.delta = nested;
  assert.ok(
    validateWaggleV0Packet(deep).some((error) => error.includes("maximum nesting depth"))
  );

  const wide = packet() as unknown as Record<string, unknown>;
  wide.delta = { items: Array.from({ length: 1_025 }, () => "item") };
  assert.ok(
    validateWaggleV0Packet(wide).some((error) => error.includes("maximum collection size"))
  );
});

test("Kea rejects codec-envelope values that disagree with the registered manifest", () => {
  const message = createWaggleV0Message({
    missionId: "mission_client_case",
    workNodeId: "work_triage",
    senderAgentId: "agent_analysis",
    receiverActorIds: ["human_reviewer"],
    contextPackId: "context_case_17",
    packet: packet(),
    createdAt: "2026-08-05T00:00:00.000Z",
  });
  message.codec.transport = "different-transport" as "mission-delta";
  const { service } = createWaggleV0FixtureKea();
  const result = service.ingest(message);
  assert.equal(result.interpretation.disposition, "rejected");
  assert.ok(
    result.interpretation.watchSignals.some((signal) => signal.code === "manifest-mismatch")
  );
});

test("filesystem content storage rejects untrusted content-hash paths", () => {
  const root = mkdtempSync(join(tmpdir(), "waggle-content-"));
  try {
    const store = new FileWaggleContentStore(root);
    assert.throws(
      () => store.has({ objectId: "invalid", contentHash: "../../outside", bytes: 0 }),
      /64 lowercase hexadecimal/
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("file ledger detects tampering and fails closed under a second writer", () => {
  const root = mkdtempSync(join(tmpdir(), "kea-ledger-"));
  try {
    const ledger = new FileKeaLedger(root);
    const message = createFixtureMessage();
    ledger.append("message", message.messageId, message, "2026-08-05T00:00:00.000Z");
    assert.equal(ledger.read().length, 1);

    const original = readFileSync(ledger.path, "utf8");
    writeFileSync(ledger.path, original.replace("mission_fixture_1", "mission_fixture_2"));
    assert.throws(() => ledger.read(), /hash mismatch/);

    writeFileSync(ledger.path, original);
    writeFileSync(`${ledger.path}.lock`, "held");
    assert.throws(
      () => ledger.append("message", message.messageId, message),
      /locked by another writer/
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
