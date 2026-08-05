import { canonicalBytes, contentId, hashCanonical } from "./canonical.js";
import { messageEvents, verifyKeaLedger, type KeaLedger } from "./ledger.js";
import type { KeaRegistryLike } from "./registry.js";
import { assertValidKeaRawMessage } from "./validation.js";
import type {
  KeaAlternativeReading,
  KeaCorrection,
  KeaDecomposition,
  KeaInterpretation,
  KeaLedgerEvent,
  KeaRawMessage,
  KeaReplay,
  KeaSemanticClaim,
  KeaWatchSignal,
} from "./types.js";

export interface KeaDecodedMessage {
  humanGloss: string;
  semanticClaims: KeaSemanticClaim[];
  alternativeReadings?: KeaAlternativeReading[];
  proposedMissionDelta?: unknown;
  reconstructedPayload?: unknown;
  taskRequiredKeys?: string[];
  /** Decoder-supplied diagnostic only; never qualification evidence. */
  behavioralParity?: number;
  outOfDistribution?: boolean;
}

export interface KeaDecoder {
  decoderId: string;
  decoderVersion: string;
  codecId: string;
  codecVersion: string;
  decode(message: KeaRawMessage): KeaDecodedMessage;
}

export interface KeaServiceOptions {
  registry: KeaRegistryLike;
  ledger: KeaLedger;
  /** The reference implementation stays fixture-only. */
  fixtureOnly?: boolean;
  maxUndecodableBytes?: number;
  clock?: () => string;
}

export interface KeaIngestResult {
  message: KeaRawMessage;
  interpretation: KeaInterpretation;
  duplicate: boolean;
}

function decoderKey(codecId: string, codecVersion: string): string {
  return `${codecId}@${codecVersion}`;
}

function objectKeys(payload: unknown): string[] {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return [];
  return Object.keys(payload as Record<string, unknown>).sort();
}

function decompose(payload: unknown, required: string[]): KeaDecomposition {
  const transmitted = objectKeys(payload);
  const requiredSet = new Set(required);
  return {
    taskRequiredKeys: [...requiredSet].sort(),
    excessKeys: transmitted.filter((key) => !requiredSet.has(key)),
    transmittedKeyCount: transmitted.length,
  };
}

function cloneMessage(message: KeaRawMessage): KeaRawMessage {
  return structuredClone(message);
}

function recordedMessages(events: readonly KeaLedgerEvent[]): KeaRawMessage[] {
  return events
    .filter((event) => event.kind === "message")
    .map((event) => event.data as KeaRawMessage);
}

function idempotencyEnvelope(message: KeaRawMessage): Omit<KeaRawMessage, "messageId"> {
  const { messageId: _messageId, ...envelope } = message;
  return envelope;
}

/**
 * Return the canonical recorded message for an exact retry. Reusing either a
 * message ID or an idempotency key for different content fails closed.
 */
function findExistingMessageId(
  events: readonly KeaLedgerEvent[],
  message: KeaRawMessage
): string | null {
  const messages = recordedMessages(events);
  const sameId = messages.find((candidate) => candidate.messageId === message.messageId);
  if (sameId) {
    if (hashCanonical(sameId) !== hashCanonical(message)) {
      throw new Error(`Kea message ${message.messageId} is immutable`);
    }
    return sameId.messageId;
  }

  const sameKey = messages.find(
    (candidate) =>
      candidate.idempotencyKey === message.idempotencyKey &&
      candidate.codec.codecId === message.codec.codecId &&
      candidate.codec.codecVersion === message.codec.codecVersion
  );
  if (!sameKey) return null;
  if (
    hashCanonical(idempotencyEnvelope(sameKey)) !==
    hashCanonical(idempotencyEnvelope(message))
  ) {
    throw new Error(
      `Kea idempotency key ${message.idempotencyKey} conflicts with message ${sameKey.messageId}`
    );
  }
  return sameKey.messageId;
}

function assertCausalParents(events: readonly KeaLedgerEvent[], message: KeaRawMessage): void {
  const uniqueParents = new Set(message.causalParentIds);
  if (uniqueParents.size !== message.causalParentIds.length) {
    throw new Error(`Kea message ${message.messageId} contains duplicate causal parents`);
  }
  const messages = recordedMessages(events);
  const byId = new Map(messages.map((candidate) => [candidate.messageId, candidate]));
  for (const parentId of message.causalParentIds) {
    if (parentId === message.messageId) {
      throw new Error(`Kea message ${message.messageId} cannot be its own causal parent`);
    }
    const parent = byId.get(parentId);
    if (!parent) {
      throw new Error(`Kea causal parent ${parentId} does not preexist`);
    }
    if (parent.missionId !== message.missionId) {
      throw new Error(
        `Kea causal parent ${parentId} belongs to a different mission`
      );
    }
  }
}

class ConcurrentDuplicateIngest extends Error {
  constructor(readonly recordedMessageId: string) {
    super(`Kea message ${recordedMessageId} was committed concurrently`);
  }
}

export class KeaService {
  readonly fixtureOnly: boolean;
  readonly maxUndecodableBytes: number;
  private readonly registry: KeaRegistryLike;
  private readonly ledger: KeaLedger;
  private readonly clock: () => string;
  private readonly decoders = new Map<string, KeaDecoder>();

  constructor(options: KeaServiceOptions) {
    this.registry = options.registry;
    this.ledger = options.ledger;
    this.fixtureOnly = options.fixtureOnly !== false;
    this.maxUndecodableBytes = Math.max(0, options.maxUndecodableBytes ?? 0);
    this.clock = options.clock || (() => new Date().toISOString());
  }

  registerDecoder(decoder: KeaDecoder): void {
    const manifest = this.registry.get(decoder.codecId, decoder.codecVersion);
    if (!manifest) {
      throw new Error(`Register Kea codec ${decoder.codecId}@${decoder.codecVersion} first`);
    }
    if (
      manifest.decoderId !== decoder.decoderId ||
      manifest.decoderVersion !== decoder.decoderVersion
    ) {
      throw new Error("Kea decoder identity does not match the immutable codec manifest");
    }
    this.decoders.set(decoderKey(decoder.codecId, decoder.codecVersion), decoder);
  }

  ingest(input: KeaRawMessage): KeaIngestResult {
    assertValidKeaRawMessage(input);
    const message = cloneMessage(input);
    if (this.fixtureOnly && message.fixture !== true) {
      throw new Error("This Kea reference implementation accepts fixtures only");
    }
    const actualHash = hashCanonical(message.payload);
    const actualBytes = canonicalBytes(message.payload);
    if (message.payloadHash !== actualHash) {
      throw new Error(`Kea payload hash mismatch for ${message.messageId}`);
    }
    if (message.payloadBytes !== actualBytes) {
      throw new Error(`Kea payload byte count mismatch for ${message.messageId}`);
    }

    const snapshot = this.ledger.read();
    verifyKeaLedger(snapshot);
    const existingMessageId = findExistingMessageId(snapshot, message);
    if (existingMessageId) return this.duplicateResult(existingMessageId);
    assertCausalParents(snapshot, message);

    const manifest = this.registry.get(message.codec.codecId, message.codec.codecVersion);
    const decoder = this.decoders.get(decoderKey(message.codec.codecId, message.codec.codecVersion));
    const signals: KeaWatchSignal[] = [];

    if (!manifest) {
      signals.push({
        code: "unknown-codec",
        severity: "block",
        detail: `Codec ${message.codec.codecId}@${message.codec.codecVersion} is not registered`,
      });
    } else {
      const envelopeMatchesManifest =
        message.codec.languageId === manifest.languageId &&
        message.codec.languageVersion === manifest.languageVersion &&
        message.codec.transport === manifest.transport &&
        message.codec.compatibilityDomain === manifest.compatibilityDomain;
      if (!envelopeMatchesManifest) {
        signals.push({
          code: "manifest-mismatch",
          severity: "block",
          detail: "Message codec envelope does not match the registered manifest",
        });
      }
      if (!manifest.allowedMessageClasses.includes(message.messageClass)) {
        signals.push({
          code: "out-of-distribution",
          severity: "block",
          detail: `Message class ${message.messageClass} is outside the codec manifest`,
        });
      }
      if (actualBytes > manifest.maxPayloadBytes) {
        signals.push({
          code: "payload-too-large",
          severity: "block",
          detail: `${actualBytes} bytes exceeds manifest limit ${manifest.maxPayloadBytes}`,
        });
      }
    }

    if (manifest && !decoder) {
      signals.push({
        code: "unknown-decoder",
        severity: "block",
        detail: `Decoder ${manifest.decoderId}@${manifest.decoderVersion} is unavailable`,
      });
    }

    let decoded: KeaDecodedMessage | null = null;
    if (manifest && decoder && !signals.some((signal) => signal.severity === "block")) {
      decoded = decoder.decode(message);
      if (decoded.outOfDistribution) {
        signals.push({
          code: "out-of-distribution",
          severity: "block",
          detail: "Decoder marked the payload out of distribution",
        });
      }
    }

    const exactRoundTrip =
      decoded?.reconstructedPayload === undefined
        ? undefined
        : hashCanonical(decoded.reconstructedPayload) === message.payloadHash;
    if (manifest?.deterministic && decoded && exactRoundTrip !== true) {
      signals.push({
        code: "decoder-disagreement",
        severity: "block",
        detail: "Deterministic decoder did not exactly reconstruct the payload",
      });
    }

    const undecodableBytes = decoded ? 0 : actualBytes;
    if (undecodableBytes > this.maxUndecodableBytes) {
      signals.push({
        code: "undecodable-capacity",
        severity: "block",
        detail: `${undecodableBytes} undecodable bytes exceeds budget ${this.maxUndecodableBytes}`,
      });
    }

    const maxPayloadBytes = manifest?.maxPayloadBytes ?? 0;
    const budgetExceeded =
      actualBytes > maxPayloadBytes || undecodableBytes > this.maxUndecodableBytes;
    const blocked = signals.some((signal) => signal.severity === "block");
    const disposition: KeaInterpretation["disposition"] = blocked
      ? "rejected"
      : exactRoundTrip === true
        ? "verified"
        : decoded
          ? "qualified"
          : "abstained";
    const createdAt = this.clock();
    const interpretationCore = {
      messageId: message.messageId,
      decoderId: decoder?.decoderId || manifest?.decoderId || "unavailable",
      decoderVersion: decoder?.decoderVersion || manifest?.decoderVersion || "unavailable",
      contextPackId: message.contextPackId,
      humanGloss: decoded?.humanGloss || "Kea abstained: no verified decoder is available.",
      semanticClaims: decoded?.semanticClaims || [],
      alternativeReadings: decoded?.alternativeReadings || [],
      proposedMissionDelta: decoded?.proposedMissionDelta,
      verification: {
        exactRoundTrip,
        behavioralParity: decoded?.behavioralParity,
        policyParity: "not-evaluated" as const,
        outOfDistribution: Boolean(decoded?.outOfDistribution),
        payloadHashVerified: true,
      },
      watchSignals: signals,
      decomposition: decompose(message.payload, decoded?.taskRequiredKeys || []),
      budget: {
        payloadBytes: actualBytes,
        maxPayloadBytes,
        undecodableBytes,
        maxUndecodableBytes: this.maxUndecodableBytes,
        exceeded: budgetExceeded,
      },
      disposition,
      authorityGranted: false as const,
      rawPayloadHash: message.payloadHash,
      createdAt,
    };
    const interpretation: KeaInterpretation = {
      interpretationId: contentId("keaint", interpretationCore),
      ...interpretationCore,
    };

    try {
      this.ledger.appendBatch(
        [
          {
            kind: "message",
            messageId: message.messageId,
            data: message,
            at: message.createdAt,
          },
          {
            kind: "interpretation",
            messageId: message.messageId,
            data: interpretation,
            at: createdAt,
          },
        ],
        (currentEvents) => {
          const committedMessageId = findExistingMessageId(currentEvents, message);
          if (committedMessageId) throw new ConcurrentDuplicateIngest(committedMessageId);
          assertCausalParents(currentEvents, message);
        }
      );
    } catch (error) {
      if (error instanceof ConcurrentDuplicateIngest) {
        return this.duplicateResult(error.recordedMessageId);
      }
      throw error;
    }
    return { message, interpretation, duplicate: false };
  }

  correct(input: {
    interpretationId: string;
    actorId: string;
    humanGloss: string;
    reason: string;
  }): KeaCorrection {
    const events = this.ledger.read();
    const interpretationEvent = events.find(
      (event) =>
        event.kind === "interpretation" &&
        (event.data as KeaInterpretation).interpretationId === input.interpretationId
    );
    if (!interpretationEvent) throw new Error(`Unknown Kea interpretation ${input.interpretationId}`);
    if (!input.actorId.trim() || !input.humanGloss.trim() || !input.reason.trim()) {
      throw new Error("Kea correction requires actor, gloss, and reason");
    }
    const createdAt = this.clock();
    const core = {
      interpretationId: input.interpretationId,
      messageId: interpretationEvent.messageId,
      actorId: input.actorId.trim(),
      humanGloss: input.humanGloss.trim(),
      reason: input.reason.trim(),
      createdAt,
    };
    const correction: KeaCorrection = {
      correctionId: contentId("keacorr", core),
      ...core,
    };
    this.ledger.append("correction", correction.messageId, correction, createdAt);
    return correction;
  }

  replay(messageId: string): KeaReplay {
    const replay = this.replayOrNull(messageId);
    if (!replay) throw new Error(`Unknown Kea message ${messageId}`);
    return replay;
  }

  listMessages(limit = 100): KeaRawMessage[] {
    const events = this.ledger.read();
    verifyKeaLedger(events);
    return events
      .filter((event) => event.kind === "message")
      .slice(-Math.max(1, Math.min(500, limit)))
      .reverse()
      .map((event) => structuredClone(event.data as KeaRawMessage));
  }

  status() {
    const events = this.ledger.read();
    const verification = verifyKeaLedger(events);
    return {
      product: "Kea",
      mode: this.fixtureOnly ? "fixture-only" : "live-gated",
      registryEntries: this.registry.list().length,
      decoders: this.decoders.size,
      ledgerEvents: events.length,
      messages: events.filter((event) => event.kind === "message").length,
      interpretations: events.filter((event) => event.kind === "interpretation").length,
      corrections: events.filter((event) => event.kind === "correction").length,
      chainVerified: verification.ok,
      authorityExecution: false,
      liveTrafficAccepted: !this.fixtureOnly,
    };
  }

  private replayOrNull(messageId: string): KeaReplay | null {
    const events = this.ledger.read();
    verifyKeaLedger(events);
    const selected = messageEvents(events, messageId);
    const messageEvent = selected.find((event) => event.kind === "message");
    if (!messageEvent) return null;
    return {
      message: structuredClone(messageEvent.data as KeaRawMessage),
      interpretations: selected
        .filter((event) => event.kind === "interpretation")
        .map((event) => structuredClone(event.data as KeaInterpretation)),
      corrections: selected
        .filter((event) => event.kind === "correction")
        .map((event) => structuredClone(event.data as KeaCorrection)),
      events: selected,
      chainVerified: true,
    };
  }

  private duplicateResult(messageId: string): KeaIngestResult {
    const existing = this.replayOrNull(messageId);
    if (!existing) throw new Error(`Kea duplicate ${messageId} disappeared from the ledger`);
    const interpretation = existing.interpretations.at(-1);
    if (!interpretation) throw new Error(`Kea replay ${messageId} has no interpretation`);
    return { message: existing.message, interpretation, duplicate: true };
  }
}
