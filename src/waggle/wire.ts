import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import {
  canonicalBytes,
  canonicalJson,
  contentId,
  hashCanonical,
} from "../kea/canonical.js";
import type { KeaRawMessage } from "../kea/types.js";
import {
  WAGGLE_V0_CODEC_ID,
  WAGGLE_V0_CODEC_VERSION,
  validateWaggleV0Packet,
} from "./codec.js";
import type {
  WaggleContentRef,
  WaggleV0Message,
  WaggleV0Packet,
} from "./types.js";

export interface WaggleContentStore {
  put(value: unknown): WaggleContentRef;
  get(ref: WaggleContentRef): unknown;
  has(ref: WaggleContentRef): boolean;
}

export class MemoryWaggleContentStore implements WaggleContentStore {
  private readonly objects = new Map<string, string>();

  put(value: unknown): WaggleContentRef {
    const encoded = canonicalJson(value);
    const contentHash = hashCanonical(value);
    this.objects.set(contentHash, encoded);
    return {
      objectId: `waggleobj_${contentHash.slice(0, 20)}`,
      contentHash,
      bytes: Buffer.byteLength(encoded, "utf8"),
    };
  }

  get(ref: WaggleContentRef): unknown {
    const encoded = this.objects.get(ref.contentHash);
    if (!encoded) throw new Error(`Unknown Waggle object ${ref.objectId}`);
    if (hashCanonical(JSON.parse(encoded)) !== ref.contentHash) {
      throw new Error(`Waggle object ${ref.objectId} failed integrity verification`);
    }
    return JSON.parse(encoded) as unknown;
  }

  has(ref: WaggleContentRef): boolean {
    return this.objects.has(ref.contentHash);
  }
}

export class FileWaggleContentStore implements WaggleContentStore {
  constructor(readonly root: string) {}

  private path(contentHash: string): string {
    if (!/^[a-f0-9]{64}$/.test(contentHash)) {
      throw new Error("Waggle content hash must be 64 lowercase hexadecimal characters");
    }
    return join(this.root, "objects", contentHash.slice(0, 2), `${contentHash}.json`);
  }

  put(value: unknown): WaggleContentRef {
    const encoded = canonicalJson(value);
    const contentHash = hashCanonical(value);
    const path = this.path(contentHash);
    if (!existsSync(path)) {
      mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
      const temp = `${path}.tmp-${process.pid}`;
      writeFileSync(temp, `${encoded}\n`, { encoding: "utf8", mode: 0o600 });
      renameSync(temp, path);
      try {
        chmodSync(path, 0o600);
      } catch {
        /* best effort */
      }
    }
    return {
      objectId: `waggleobj_${contentHash.slice(0, 20)}`,
      contentHash,
      bytes: Buffer.byteLength(encoded, "utf8"),
    };
  }

  get(ref: WaggleContentRef): unknown {
    const path = this.path(ref.contentHash);
    if (!existsSync(path)) throw new Error(`Unknown Waggle object ${ref.objectId}`);
    const encoded = readFileSync(path, "utf8");
    if (ref.bytes !== Buffer.byteLength(encoded.trimEnd(), "utf8")) {
      throw new Error(`Waggle object ${ref.objectId} failed byte-count verification`);
    }
    const value = JSON.parse(encoded) as unknown;
    if (hashCanonical(value) !== ref.contentHash) {
      throw new Error(`Waggle object ${ref.objectId} failed integrity verification`);
    }
    return value;
  }

  has(ref: WaggleContentRef): boolean {
    return existsSync(this.path(ref.contentHash));
  }
}

export function encodeWaggleV0(packet: WaggleV0Packet): Buffer {
  const errors = validateWaggleV0Packet(packet);
  if (errors.length) throw new Error(`Invalid Waggle v0 packet: ${errors.join("; ")}`);
  return Buffer.from(canonicalJson(packet), "utf8");
}

export function decodeWaggleV0(encoded: Buffer | string): WaggleV0Packet {
  const packet = JSON.parse(Buffer.isBuffer(encoded) ? encoded.toString("utf8") : encoded) as WaggleV0Packet;
  const errors = validateWaggleV0Packet(packet);
  if (errors.length) throw new Error(`Invalid Waggle v0 packet: ${errors.join("; ")}`);
  return packet;
}

export function composeWaggleV0Packets(
  mode: "sequence" | "bundle",
  packets: WaggleV0Packet[]
): WaggleV0Packet {
  if (!packets.length) throw new Error("Waggle composition requires at least one packet");
  const primitiveIds = packets.flatMap((packet) =>
    packet.composition?.mode === mode
      ? packet.composition.operandIds
      : [`waggleop_${hashCanonical(packet).slice(0, 20)}`]
  );
  const operandIds =
    mode === "bundle" ? [...new Set(primitiveIds)].sort() : primitiveIds;
  const context = [...new Set(packets.flatMap((packet) => packet.references.context))].sort();
  const artifacts = [...new Set(packets.flatMap((packet) => packet.references.artifacts))].sort();
  const evidence = [...new Set(packets.flatMap((packet) => packet.references.evidence))].sort();
  return {
    protocol: "waggle.v0",
    messageClass: "state-delta",
    intent: "propose",
    operation: `compose.${mode}`,
    references: { context, artifacts, evidence },
    delta: { operandCount: operandIds.length },
    composition: { mode, operandIds },
  };
}

export function createWaggleV0Message(input: {
  messageId?: string;
  missionId: string;
  workNodeId: string;
  senderAgentId: string;
  receiverActorIds: string[];
  packet: WaggleV0Packet;
  contextPackId: string;
  artifactRefs?: string[];
  evidenceRefs?: string[];
  causalParentIds?: string[];
  authorityEffect?: KeaRawMessage["authorityEffect"];
  sensitivity?: KeaRawMessage["sensitivity"];
  createdAt?: string;
}): WaggleV0Message {
  const encoded = encodeWaggleV0(input.packet);
  const createdAt = input.createdAt || new Date().toISOString();
  const core = {
    missionId: input.missionId,
    workNodeId: input.workNodeId,
    senderAgentId: input.senderAgentId,
    packet: input.packet,
    createdAt,
  };
  return {
    messageId: input.messageId || contentId("wagglemsg", core),
    missionId: input.missionId,
    workNodeId: input.workNodeId,
    senderAgentId: input.senderAgentId,
    receiverActorIds: [...input.receiverActorIds],
    messageClass: input.packet.messageClass,
    causalParentIds: [...(input.causalParentIds || [])],
    contextPackId: input.contextPackId,
    artifactRefs: [...(input.artifactRefs || [])],
    evidenceRefs: [...(input.evidenceRefs || [])],
    codec: {
      languageId: "waggle",
      languageVersion: "0.1.0",
      codecId: WAGGLE_V0_CODEC_ID,
      codecVersion: WAGGLE_V0_CODEC_VERSION,
      compatibilityDomain: "waggle-v0-tools",
      transport: "mission-delta",
    },
    payload: structuredClone(input.packet),
    payloadHash: hashCanonical(input.packet),
    payloadBytes: encoded.byteLength,
    sensitivity: input.sensitivity || "internal",
    authorityEffect: input.authorityEffect || "proposal",
    idempotencyKey: contentId("waggleidem", core),
    createdAt,
    fixture: true,
  };
}

export function waggleWireBytes(packet: WaggleV0Packet): number {
  return canonicalBytes(packet);
}
