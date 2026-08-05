import type { KeaDecoder } from "../kea/service.js";
import type { KeaCodecManifestInput } from "../kea/registry.js";
import { canonicalBytes } from "../kea/canonical.js";
import type { KeaRawMessage } from "../kea/types.js";
import type { WaggleV0Packet } from "./types.js";

export const WAGGLE_V0_CODEC_ID = "waggle.v0.canonical-json";
export const WAGGLE_V0_CODEC_VERSION = "0.1.0";
export const KEA_WAGGLE_V0_DECODER_ID = "kea.waggle.v0.exact";
export const KEA_WAGGLE_V0_DECODER_VERSION = "0.1.0";

const IDENTIFIER = /^[a-zA-Z0-9][a-zA-Z0-9._:/@-]{0,159}$/;
const KEY = /^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/;
const MAX_PACKET_BYTES = 65_536;
const MAX_DEPTH = 24;
const MAX_COLLECTION_ITEMS = 1_024;
const MESSAGE_CLASSES = new Set([
  "observation",
  "hypothesis",
  "question",
  "proposal",
  "state-delta",
  "artifact-handoff",
  "authority-request",
  "action-result",
  "correction",
]);
const INTENTS = new Set([
  "observe",
  "hypothesize",
  "ask",
  "propose",
  "handoff",
  "request-authority",
  "report-result",
  "correct",
]);
const FORBIDDEN_KEYS = new Set([
  "text",
  "message",
  "prompt",
  "reasoning",
  "chainOfThought",
  "humanGloss",
  "description",
]);
const PACKET_KEYS = new Set([
  "protocol",
  "messageClass",
  "intent",
  "operation",
  "references",
  "delta",
  "composition",
]);
const REQUIRED_PACKET_KEYS = [
  "protocol",
  "messageClass",
  "intent",
  "operation",
  "references",
  "delta",
] as const;
const REFERENCE_KEYS = new Set(["context", "artifacts", "evidence"]);
const COMPOSITION_KEYS = new Set(["mode", "operandIds"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validateExactKeys(
  value: Record<string, unknown>,
  path: string,
  allowed: ReadonlySet<string>,
  required: readonly string[]
): string[] {
  const errors: string[] = [];
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") {
      errors.push(`${path} contains a non-string field`);
    } else if (!allowed.has(key)) {
      errors.push(`${path}.${key} is an unexpected field`);
    }
  }
  for (const key of required) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) {
      errors.push(`${path}.${key} is required`);
    }
  }
  return errors;
}

function validateValue(
  value: unknown,
  path: string,
  seen: Set<object>,
  depth = 0
): string[] {
  const errors: string[] = [];
  if (depth > MAX_DEPTH) return [`${path} exceeds maximum nesting depth ${MAX_DEPTH}`];
  if (value === null || typeof value === "boolean") return errors;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) errors.push(`${path} contains a non-finite number`);
    return errors;
  }
  if (typeof value === "string") {
    if (!IDENTIFIER.test(value)) errors.push(`${path} contains prose or an invalid symbolic token`);
    return errors;
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) return [`${path} contains a cycle`];
    if (value.length > MAX_COLLECTION_ITEMS) {
      errors.push(`${path} exceeds maximum collection size ${MAX_COLLECTION_ITEMS}`);
    }
    seen.add(value);
    value.forEach((item, index) =>
      errors.push(...validateValue(item, `${path}[${index}]`, seen, depth + 1))
    );
    seen.delete(value);
    return errors;
  }
  if (isRecord(value)) {
    if (seen.has(value)) return [`${path} contains a cycle`];
    const entries = Object.entries(value);
    if (entries.length > MAX_COLLECTION_ITEMS) {
      errors.push(`${path} exceeds maximum collection size ${MAX_COLLECTION_ITEMS}`);
    }
    seen.add(value);
    for (const [key, item] of entries) {
      if (!KEY.test(key)) errors.push(`${path}.${key} has an invalid key`);
      if (FORBIDDEN_KEYS.has(key)) errors.push(`${path}.${key} is a prose-bearing field`);
      errors.push(...validateValue(item, `${path}.${key}`, seen, depth + 1));
    }
    seen.delete(value);
    return errors;
  }
  return [`${path} contains an unsupported value`];
}

export function validateWaggleV0Packet(packet: unknown): string[] {
  const errors: string[] = [];
  if (!isRecord(packet)) return ["packet must be an object"];
  errors.push(...validateExactKeys(packet, "packet", PACKET_KEYS, REQUIRED_PACKET_KEYS));
  if (packet.protocol !== "waggle.v0") errors.push("protocol must be waggle.v0");
  if (typeof packet.messageClass !== "string" || !MESSAGE_CLASSES.has(packet.messageClass)) {
    errors.push("messageClass is invalid");
  }
  if (typeof packet.intent !== "string" || !INTENTS.has(packet.intent)) {
    errors.push("intent is invalid");
  }
  if (typeof packet.operation !== "string" || !IDENTIFIER.test(packet.operation)) {
    errors.push("operation must be a symbolic identifier");
  }
  if (!isRecord(packet.references)) {
    errors.push("references must be an object");
  } else {
    errors.push(
      ...validateExactKeys(
        packet.references,
        "packet.references",
        REFERENCE_KEYS,
        [...REFERENCE_KEYS]
      )
    );
    for (const kind of ["context", "artifacts", "evidence"] as const) {
      const refs = packet.references[kind];
      if (!Array.isArray(refs)) {
        errors.push(`${kind} references must be an array`);
        continue;
      }
      if (refs.length > MAX_COLLECTION_ITEMS) {
        errors.push(`${kind} references exceed maximum collection size ${MAX_COLLECTION_ITEMS}`);
      }
      for (const ref of refs) {
        if (typeof ref !== "string" || !IDENTIFIER.test(ref)) {
          errors.push(`${kind} reference is invalid`);
        }
      }
    }
  }
  if (packet.composition !== undefined) {
    if (!isRecord(packet.composition)) {
      errors.push("composition must be an object");
    } else {
      errors.push(
        ...validateExactKeys(
          packet.composition,
          "packet.composition",
          COMPOSITION_KEYS,
          [...COMPOSITION_KEYS]
        )
      );
      if (packet.composition.mode !== "sequence" && packet.composition.mode !== "bundle") {
        errors.push("composition mode is invalid");
      }
      if (!Array.isArray(packet.composition.operandIds)) {
        errors.push("composition operandIds must be an array");
      } else {
        if (packet.composition.operandIds.length > MAX_COLLECTION_ITEMS) {
          errors.push(`composition operands exceed maximum collection size ${MAX_COLLECTION_ITEMS}`);
        }
        for (const id of packet.composition.operandIds) {
          if (typeof id !== "string" || !IDENTIFIER.test(id)) {
            errors.push("composition operand is invalid");
          }
        }
      }
    }
  }
  if (Object.prototype.hasOwnProperty.call(packet, "delta")) {
    errors.push(...validateValue(packet.delta, "delta", new Set<object>()));
  }
  try {
    if (canonicalBytes(packet) > MAX_PACKET_BYTES) {
      errors.push(`packet exceeds maximum payload size ${MAX_PACKET_BYTES}`);
    }
  } catch {
    errors.push("packet cannot be canonically encoded");
  }
  return errors;
}

export function validateWaggleV0Envelope(message: KeaRawMessage): string[] {
  const errors = validateWaggleV0Packet(message.payload);
  if (
    isRecord(message.payload) &&
    typeof message.payload.messageClass === "string" &&
    message.payload.messageClass !== message.messageClass
  ) {
    errors.push("packet.messageClass must match message.messageClass");
  }
  return errors;
}

export function waggleV0Manifest(): KeaCodecManifestInput {
  return {
    languageId: "waggle",
    languageVersion: "0.1.0",
    codecId: WAGGLE_V0_CODEC_ID,
    codecVersion: WAGGLE_V0_CODEC_VERSION,
    transport: "mission-delta",
    compatibilityDomain: "waggle-v0-tools",
    deterministic: true,
    decoderId: KEA_WAGGLE_V0_DECODER_ID,
    decoderVersion: KEA_WAGGLE_V0_DECODER_VERSION,
    maxPayloadBytes: 65_536,
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

export function keaWaggleV0Decoder(): KeaDecoder {
  return {
    decoderId: KEA_WAGGLE_V0_DECODER_ID,
    decoderVersion: KEA_WAGGLE_V0_DECODER_VERSION,
    codecId: WAGGLE_V0_CODEC_ID,
    codecVersion: WAGGLE_V0_CODEC_VERSION,
    decode(message) {
      const payload = message.payload;
      const errors = validateWaggleV0Envelope(message);
      const packet = errors.length ? null : (payload as WaggleV0Packet);
      return {
        humanGloss: errors.length
          ? "Kea rejected an invalid Waggle v0 packet."
          : `${packet!.intent}: ${packet!.operation}`,
        semanticClaims: errors.length
          ? errors.map((error) => ({ claim: error, confidence: 1, evidenceRefs: [] }))
          : [
              {
                claim: `Waggle v0 ${packet!.messageClass} uses operation ${packet!.operation}`,
                confidence: 1,
                evidenceRefs: packet!.references.evidence,
              },
            ],
        reconstructedPayload: structuredClone(payload),
        proposedMissionDelta: packet?.delta,
        taskRequiredKeys: [
          "protocol",
          "messageClass",
          "intent",
          "operation",
          "references",
          "delta",
        ],
        behavioralParity: errors.length ? 0 : 1,
        outOfDistribution: errors.length > 0,
      };
    },
  };
}
