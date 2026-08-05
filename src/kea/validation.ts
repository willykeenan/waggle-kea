import type { KeaMessageClass, KeaRawMessage } from "./types.js";

const IDENTIFIER = /^[a-zA-Z0-9][a-zA-Z0-9._:/@-]{0,159}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const MAX_LIST_ITEMS = 1_024;

const MESSAGE_CLASSES = new Set<KeaMessageClass>([
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

const MESSAGE_KEYS = new Set([
  "messageId",
  "missionId",
  "workNodeId",
  "senderAgentId",
  "receiverActorIds",
  "messageClass",
  "causalParentIds",
  "contextPackId",
  "artifactRefs",
  "evidenceRefs",
  "codec",
  "payload",
  "payloadHash",
  "payloadBytes",
  "sensitivity",
  "authorityEffect",
  "idempotencyKey",
  "createdAt",
  "fixture",
]);

const REQUIRED_MESSAGE_KEYS = [
  "messageId",
  "missionId",
  "workNodeId",
  "senderAgentId",
  "receiverActorIds",
  "messageClass",
  "causalParentIds",
  "artifactRefs",
  "evidenceRefs",
  "codec",
  "payload",
  "payloadHash",
  "payloadBytes",
  "sensitivity",
  "authorityEffect",
  "idempotencyKey",
  "createdAt",
  "fixture",
] as const;

const CODEC_KEYS = new Set([
  "languageId",
  "languageVersion",
  "codecId",
  "codecVersion",
  "compatibilityDomain",
  "transport",
]);

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function validateExactKeys(
  value: Record<string, unknown>,
  path: string,
  allowed: ReadonlySet<string>,
  required: readonly string[],
  errors: string[]
): void {
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
}

function validateIdentifier(value: unknown, path: string, errors: string[]): void {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) {
    errors.push(`${path} must be a symbolic identifier`);
  }
}

function validateIdentifierList(
  value: unknown,
  path: string,
  errors: string[],
  options: { nonEmpty?: boolean } = {}
): void {
  if (!Array.isArray(value)) {
    errors.push(`${path} must be an array`);
    return;
  }
  if (options.nonEmpty && value.length === 0) errors.push(`${path} must not be empty`);
  if (value.length > MAX_LIST_ITEMS) {
    errors.push(`${path} exceeds maximum collection size ${MAX_LIST_ITEMS}`);
  }
  const seen = new Set<string>();
  value.forEach((item, index) => {
    validateIdentifier(item, `${path}[${index}]`, errors);
    if (typeof item === "string") {
      if (seen.has(item)) errors.push(`${path} contains duplicate identifier ${item}`);
      seen.add(item);
    }
  });
}

function validateIsoTimestamp(value: unknown, path: string, errors: string[]): void {
  if (typeof value !== "string") {
    errors.push(`${path} must be an ISO-8601 UTC timestamp`);
    return;
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    errors.push(`${path} must be an ISO-8601 UTC timestamp with millisecond precision`);
  }
}

/**
 * Validate the codec-independent Kea envelope. Codec payloads remain opaque
 * here and are validated by their registered decoder before qualification.
 */
export function validateKeaRawMessage(value: unknown): string[] {
  const errors: string[] = [];
  if (!isPlainRecord(value)) return ["message must be a plain object"];

  validateExactKeys(value, "message", MESSAGE_KEYS, REQUIRED_MESSAGE_KEYS, errors);
  validateIdentifier(value.messageId, "message.messageId", errors);
  validateIdentifier(value.missionId, "message.missionId", errors);
  validateIdentifier(value.workNodeId, "message.workNodeId", errors);
  validateIdentifier(value.senderAgentId, "message.senderAgentId", errors);
  validateIdentifierList(value.receiverActorIds, "message.receiverActorIds", errors, {
    nonEmpty: true,
  });
  validateIdentifierList(value.causalParentIds, "message.causalParentIds", errors);
  validateIdentifierList(value.artifactRefs, "message.artifactRefs", errors);
  validateIdentifierList(value.evidenceRefs, "message.evidenceRefs", errors);

  if (value.contextPackId !== undefined) {
    validateIdentifier(value.contextPackId, "message.contextPackId", errors);
  }
  if (typeof value.messageClass !== "string" || !MESSAGE_CLASSES.has(value.messageClass as KeaMessageClass)) {
    errors.push("message.messageClass is invalid");
  }

  if (!isPlainRecord(value.codec)) {
    errors.push("message.codec must be a plain object");
  } else {
    validateExactKeys(value.codec, "message.codec", CODEC_KEYS, [...CODEC_KEYS], errors);
    for (const key of CODEC_KEYS) {
      validateIdentifier(value.codec[key], `message.codec.${key}`, errors);
    }
  }

  if (typeof value.payloadHash !== "string" || !SHA256.test(value.payloadHash)) {
    errors.push("message.payloadHash must be a lowercase SHA-256 digest");
  }
  if (!Number.isSafeInteger(value.payloadBytes) || (value.payloadBytes as number) < 0) {
    errors.push("message.payloadBytes must be a non-negative safe integer");
  }
  if (!["public", "internal", "confidential", "restricted"].includes(String(value.sensitivity))) {
    errors.push("message.sensitivity is invalid");
  }
  if (!["none", "proposal", "request"].includes(String(value.authorityEffect))) {
    errors.push("message.authorityEffect is invalid");
  }
  validateIdentifier(value.idempotencyKey, "message.idempotencyKey", errors);
  validateIsoTimestamp(value.createdAt, "message.createdAt", errors);
  if (typeof value.fixture !== "boolean") errors.push("message.fixture must be boolean");

  return errors;
}

export function assertValidKeaRawMessage(value: unknown): asserts value is KeaRawMessage {
  const errors = validateKeaRawMessage(value);
  if (errors.length) throw new Error(`Invalid Kea message: ${errors.join("; ")}`);
}
