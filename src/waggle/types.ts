import type { KeaMessageClass, KeaRawMessage } from "../kea/types.js";

export type WaggleV0Intent =
  | "observe"
  | "hypothesize"
  | "ask"
  | "propose"
  | "handoff"
  | "request-authority"
  | "report-result"
  | "correct";

export type WaggleV0Scalar = null | boolean | number | string;
export type WaggleV0Value =
  | WaggleV0Scalar
  | WaggleV0Value[]
  | { [key: string]: WaggleV0Value };

export interface WaggleV0Packet {
  protocol: "waggle.v0";
  messageClass: KeaMessageClass;
  intent: WaggleV0Intent;
  operation: string;
  references: {
    context: string[];
    artifacts: string[];
    evidence: string[];
  };
  delta: WaggleV0Value;
  composition?: {
    mode: "sequence" | "bundle";
    operandIds: string[];
  };
}

export interface WaggleV0Message extends KeaRawMessage {
  payload: WaggleV0Packet;
  codec: KeaRawMessage["codec"] & {
    languageId: "waggle";
    languageVersion: "0.1.0";
    codecId: "waggle.v0.canonical-json";
    codecVersion: "0.1.0";
    compatibilityDomain: "waggle-v0-tools";
    transport: "mission-delta";
  };
}

export interface WaggleContentRef {
  objectId: string;
  contentHash: string;
  bytes: number;
}

export interface WaggleV0EvaluationReport {
  schemaVersion: "1.1.0";
  fixtureOnly: true;
  passed: boolean;
  e1Economics: {
    status: "not_evaluated";
    requiredEvidence: string[];
  };
  fixtureByteProxy: {
    proseBaselineBytes: number;
    waggleWireBytes: number;
    sharedContextBytes: number;
    totalWaggleBytes: number;
    reduction: number;
    comparableBaseline: false;
    fixtureThreshold: number;
    fixtureThresholdMet: boolean;
    note: string;
  };
  e2: {
    messages: number;
    exactReconstructions: number;
    fidelity: number;
    gate: number;
    passed: boolean;
  };
  checks: Array<{ id: string; passed: boolean; detail: string }>;
  modelCalls: 0;
  externalCalls: 0;
  authorityEffectsExecuted: 0;
  generatedAt: string;
}
