import {
  chmodSync,
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { canonicalJson, contentId, hashCanonical } from "./canonical.js";
import { defaultKeaRoot } from "./paths.js";
import type {
  KeaCorrection,
  KeaInterpretation,
  KeaLedgerEvent,
  KeaLedgerEventKind,
  KeaRawMessage,
} from "./types.js";

export type KeaLedgerData = KeaRawMessage | KeaInterpretation | KeaCorrection;

export interface KeaLedger {
  append(kind: KeaLedgerEventKind, messageId: string, data: KeaLedgerData, at?: string): KeaLedgerEvent;
  read(): KeaLedgerEvent[];
}

function eventCore(event: Omit<KeaLedgerEvent, "eventHash">) {
  return event;
}

function calculateEventHash(event: Omit<KeaLedgerEvent, "eventHash">): string {
  return hashCanonical(eventCore(event));
}

export function verifyKeaLedger(events: KeaLedgerEvent[]): {
  ok: boolean;
  events: number;
  lastHash: string;
} {
  let previousHash = "GENESIS";
  for (let index = 0; index < events.length; index++) {
    const event = events[index];
    if (event.sequence !== index + 1) throw new Error(`Kea ledger sequence gap at ${index + 1}`);
    if (event.previousHash !== previousHash) {
      throw new Error(`Kea ledger previous hash mismatch at ${event.sequence}`);
    }
    const { eventHash, ...withoutHash } = event;
    if (calculateEventHash(withoutHash) !== eventHash) {
      throw new Error(`Kea ledger hash mismatch at ${event.sequence}`);
    }
    previousHash = eventHash;
  }
  return { ok: true, events: events.length, lastHash: previousHash };
}

function buildEvent(
  events: KeaLedgerEvent[],
  kind: KeaLedgerEventKind,
  messageId: string,
  data: KeaLedgerData,
  at = new Date().toISOString()
): KeaLedgerEvent {
  const sequence = events.length + 1;
  const previousHash = events.at(-1)?.eventHash || "GENESIS";
  const eventId = contentId("keaevt", { sequence, kind, messageId, at, data });
  const withoutHash: Omit<KeaLedgerEvent, "eventHash"> = {
    schemaVersion: "1.0.0",
    sequence,
    eventId,
    kind,
    messageId,
    at,
    previousHash,
    data: structuredClone(data),
  };
  return { ...withoutHash, eventHash: calculateEventHash(withoutHash) };
}

export class MemoryKeaLedger implements KeaLedger {
  private events: KeaLedgerEvent[];

  constructor(initial: KeaLedgerEvent[] = []) {
    verifyKeaLedger(initial);
    this.events = initial.map((event) => structuredClone(event));
  }

  append(
    kind: KeaLedgerEventKind,
    messageId: string,
    data: KeaLedgerData,
    at?: string
  ): KeaLedgerEvent {
    const event = buildEvent(this.events, kind, messageId, data, at);
    this.events.push(event);
    return structuredClone(event);
  }

  read(): KeaLedgerEvent[] {
    return this.events.map((event) => structuredClone(event));
  }
}

export class FileKeaLedger implements KeaLedger {
  readonly path: string;

  constructor(root = defaultKeaRoot()) {
    this.path = join(root, "ledger.jsonl");
  }

  read(): KeaLedgerEvent[] {
    if (!existsSync(this.path)) return [];
    const events = readFileSync(this.path, "utf8")
      .split("\n")
      .filter(Boolean)
      .map((line, index) => {
        try {
          return JSON.parse(line) as KeaLedgerEvent;
        } catch {
          throw new Error(`Kea ledger contains invalid JSON at line ${index + 1}`);
        }
      });
    verifyKeaLedger(events);
    return events;
  }

  append(
    kind: KeaLedgerEventKind,
    messageId: string,
    data: KeaLedgerData,
    at?: string
  ): KeaLedgerEvent {
    const directory = dirname(this.path);
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const lockPath = `${this.path}.lock`;
    let lockFd: number;
    try {
      lockFd = openSync(lockPath, "wx", 0o600);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") {
        throw new Error("Kea ledger is locked by another writer; retry after it completes");
      }
      throw error;
    }

    const temp = `${this.path}.tmp-${process.pid}`;
    try {
      const events = this.read();
      const event = buildEvent(events, kind, messageId, data, at);
      const next = [...events, event].map((item) => canonicalJson(item)).join("\n");
      writeFileSync(temp, `${next}\n`, { encoding: "utf8", mode: 0o600 });
      renameSync(temp, this.path);
      try {
        chmodSync(directory, 0o700);
        chmodSync(this.path, 0o600);
      } catch {
        /* best effort on filesystems without POSIX modes */
      }
      return structuredClone(event);
    } finally {
      try {
        if (existsSync(temp)) unlinkSync(temp);
      } catch {
        /* best effort cleanup */
      }
      closeSync(lockFd);
      try {
        unlinkSync(lockPath);
      } catch {
        /* a stale lock fails closed on the next write */
      }
    }
  }
}

export function messageEvents(events: KeaLedgerEvent[], messageId: string): KeaLedgerEvent[] {
  const selected = events.filter((event) => event.messageId === messageId);
  verifyKeaLedger(events);
  return selected.map((event) => structuredClone(event));
}
