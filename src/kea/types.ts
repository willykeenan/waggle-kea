export type KeaMessageClass =
  | "observation"
  | "hypothesis"
  | "question"
  | "proposal"
  | "state-delta"
  | "artifact-handoff"
  | "authority-request"
  | "action-result"
  | "correction";

export type KeaDisposition =
  | "verified"
  | "qualified"
  | "abstained"
  | "rejected";

export interface KeaCodecManifest {
  languageId: string;
  languageVersion: string;
  codecId: string;
  codecVersion: string;
  transport: string;
  compatibilityDomain: string;
  deterministic: boolean;
  decoderId: string;
  decoderVersion: string;
  maxPayloadBytes: number;
  allowedMessageClasses: KeaMessageClass[];
  status: "fixture" | "experimental" | "approved" | "retired";
  registeredAt: string;
  integrityHash: string;
}

export interface KeaRawMessage {
  messageId: string;
  missionId: string;
  workNodeId: string;
  senderAgentId: string;
  receiverActorIds: string[];
  messageClass: KeaMessageClass;
  causalParentIds: string[];
  contextPackId?: string;
  artifactRefs: string[];
  evidenceRefs: string[];
  codec: Pick<
    KeaCodecManifest,
    | "languageId"
    | "languageVersion"
    | "codecId"
    | "codecVersion"
    | "compatibilityDomain"
    | "transport"
  >;
  payload: unknown;
  payloadHash: string;
  payloadBytes: number;
  sensitivity: "public" | "internal" | "confidential" | "restricted";
  authorityEffect: "none" | "proposal" | "request";
  idempotencyKey: string;
  createdAt: string;
  /** The reference implementation accepts sanitized fixtures only. */
  fixture: boolean;
}

export interface KeaSemanticClaim {
  claim: string;
  confidence: number;
  evidenceRefs: string[];
}

export interface KeaAlternativeReading {
  reading: string;
  confidence: number;
}

export interface KeaWatchSignal {
  code:
    | "unknown-codec"
    | "unknown-decoder"
    | "payload-too-large"
    | "manifest-mismatch"
    | "undecodable-capacity"
    | "out-of-distribution"
    | "causal-gap"
    | "decoder-disagreement";
  severity: "info" | "warning" | "block";
  detail: string;
}

export interface KeaDecomposition {
  taskRequiredKeys: string[];
  excessKeys: string[];
  transmittedKeyCount: number;
}

export interface KeaBudgetResult {
  payloadBytes: number;
  maxPayloadBytes: number;
  undecodableBytes: number;
  maxUndecodableBytes: number;
  exceeded: boolean;
}

export interface KeaInterpretation {
  interpretationId: string;
  messageId: string;
  decoderId: string;
  decoderVersion: string;
  contextPackId?: string;
  humanGloss: string;
  semanticClaims: KeaSemanticClaim[];
  alternativeReadings: KeaAlternativeReading[];
  proposedMissionDelta?: unknown;
  verification: {
    exactRoundTrip?: boolean;
    behavioralParity?: number;
    secondaryDecoderAgreement?: number;
    policyParity: "not-evaluated" | "passed" | "failed";
    outOfDistribution: boolean;
    payloadHashVerified: boolean;
  };
  watchSignals: KeaWatchSignal[];
  decomposition: KeaDecomposition;
  budget: KeaBudgetResult;
  disposition: KeaDisposition;
  authorityGranted: false;
  rawPayloadHash: string;
  createdAt: string;
}

export interface KeaCorrection {
  correctionId: string;
  interpretationId: string;
  messageId: string;
  actorId: string;
  humanGloss: string;
  reason: string;
  createdAt: string;
}

export type KeaLedgerEventKind =
  | "message"
  | "interpretation"
  | "correction";

export interface KeaLedgerEvent {
  schemaVersion: "1.0.0";
  sequence: number;
  eventId: string;
  kind: KeaLedgerEventKind;
  messageId: string;
  at: string;
  previousHash: string;
  eventHash: string;
  data: KeaRawMessage | KeaInterpretation | KeaCorrection;
}

export interface KeaReplay {
  message: KeaRawMessage;
  interpretations: KeaInterpretation[];
  corrections: KeaCorrection[];
  events: KeaLedgerEvent[];
  chainVerified: boolean;
}

export interface KeaEvaluationCheck {
  id: string;
  passed: boolean;
  detail: string;
}

export interface KeaEvaluationReport {
  schemaVersion: "1.0.0";
  fixtureOnly: true;
  passed: boolean;
  checks: KeaEvaluationCheck[];
  messages: number;
  interpretations: number;
  ledgerEvents: number;
  generatedAt: string;
  externalCalls: 0;
  modelCalls: 0;
  authorityEffectsExecuted: 0;
}
