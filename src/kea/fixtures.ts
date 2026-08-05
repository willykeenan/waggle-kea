import { canonicalBytes, contentId, hashCanonical } from "./canonical.js";
import type { KeaDecoder } from "./service.js";
import type { KeaCodecManifestInput } from "./registry.js";
import type { KeaMessageClass, KeaRawMessage } from "./types.js";

export const KEA_FIXTURE_CODEC_ID = "kea.fixture-json";
export const KEA_FIXTURE_CODEC_VERSION = "1.0.0";
export const KEA_FIXTURE_DECODER_ID = "kea.fixture-json.exact";
export const KEA_FIXTURE_DECODER_VERSION = "1.0.0";

export function fixtureCodecManifest(): KeaCodecManifestInput {
  return {
    languageId: "kea-fixture",
    languageVersion: "1.0.0",
    codecId: KEA_FIXTURE_CODEC_ID,
    codecVersion: KEA_FIXTURE_CODEC_VERSION,
    transport: "fixture-json",
    compatibilityDomain: "sanitized-fixtures-only",
    deterministic: true,
    decoderId: KEA_FIXTURE_DECODER_ID,
    decoderVersion: KEA_FIXTURE_DECODER_VERSION,
    maxPayloadBytes: 16_384,
    allowedMessageClasses: [
      "observation",
      "hypothesis",
      "question",
      "proposal",
      "state-delta",
      "artifact-handoff",
      "authority-request",
      "action-result",
      "correction",
    ],
    status: "fixture",
    registeredAt: "2026-07-11T00:00:00.000Z",
  };
}

export function fixtureJsonDecoder(): KeaDecoder {
  return {
    decoderId: KEA_FIXTURE_DECODER_ID,
    decoderVersion: KEA_FIXTURE_DECODER_VERSION,
    codecId: KEA_FIXTURE_CODEC_ID,
    codecVersion: KEA_FIXTURE_CODEC_VERSION,
    decode(message) {
      const payload = message.payload as Record<string, unknown>;
      const plainObject = Boolean(payload && typeof payload === "object" && !Array.isArray(payload));
      const intent = plainObject && typeof payload.intent === "string" ? payload.intent : message.messageClass;
      const operation = plainObject && typeof payload.operation === "string" ? payload.operation : "record";
      const claims = plainObject
        ? Object.keys(payload)
            .sort()
            .map((key) => ({
              claim: `${key} is present in the deterministic fixture payload`,
              confidence: 1,
              evidenceRefs: message.evidenceRefs,
            }))
        : [];
      return {
        humanGloss: `${intent}: ${operation}`,
        semanticClaims: claims,
        reconstructedPayload: structuredClone(message.payload),
        proposedMissionDelta: plainObject ? payload.missionDelta : undefined,
        taskRequiredKeys: ["intent", "operation", "references"],
        behavioralParity: 1,
        outOfDistribution: !plainObject,
      };
    },
  };
}

export function createFixtureMessage(input?: {
  messageId?: string;
  missionId?: string;
  workNodeId?: string;
  messageClass?: KeaMessageClass;
  payload?: Record<string, unknown>;
  createdAt?: string;
  codecId?: string;
  codecVersion?: string;
}): KeaRawMessage {
  const payload = input?.payload || {
    intent: "inspect",
    operation: "compare-fixture",
    references: ["artifact_fixture_1"],
    missionDelta: { status: "review" },
  };
  const createdAt = input?.createdAt || "2026-07-11T00:00:01.000Z";
  const core = {
    missionId: input?.missionId || "mission_fixture_1",
    workNodeId: input?.workNodeId || "work_fixture_1",
    payload,
    createdAt,
  };
  return {
    messageId: input?.messageId || contentId("keamsg", core),
    missionId: core.missionId,
    workNodeId: core.workNodeId,
    senderAgentId: "agent_fixture_sender",
    receiverActorIds: ["agent_fixture_receiver"],
    messageClass: input?.messageClass || "state-delta",
    causalParentIds: [],
    contextPackId: "context_fixture_1",
    artifactRefs: ["artifact_fixture_1"],
    evidenceRefs: ["evidence_fixture_1"],
    codec: {
      languageId: "kea-fixture",
      languageVersion: "1.0.0",
      codecId: input?.codecId || KEA_FIXTURE_CODEC_ID,
      codecVersion: input?.codecVersion || KEA_FIXTURE_CODEC_VERSION,
      compatibilityDomain: "sanitized-fixtures-only",
      transport: "fixture-json",
    },
    payload,
    payloadHash: hashCanonical(payload),
    payloadBytes: canonicalBytes(payload),
    sensitivity: "internal",
    authorityEffect: "proposal",
    idempotencyKey: contentId("idem", core),
    createdAt,
    fixture: true,
  };
}
