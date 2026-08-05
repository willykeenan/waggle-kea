import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
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

export interface KeaLedgerAppend {
  kind: KeaLedgerEventKind;
  messageId: string;
  data: KeaLedgerData;
  at?: string;
}

export type KeaLedgerGuard = (events: readonly KeaLedgerEvent[]) => void;

export interface KeaLedger {
  append(kind: KeaLedgerEventKind, messageId: string, data: KeaLedgerData, at?: string): KeaLedgerEvent;
  appendBatch(entries: readonly KeaLedgerAppend[], guard?: KeaLedgerGuard): KeaLedgerEvent[];
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
    const expectedEventId = contentId("keaevt", {
      sequence: event.sequence,
      kind: event.kind,
      messageId: event.messageId,
      at: event.at,
      data: event.data,
    });
    if (event.eventId !== expectedEventId) {
      throw new Error(`Kea ledger event ID mismatch at ${event.sequence}`);
    }
    previousHash = eventHash;
  }
  return { ok: true, events: events.length, lastHash: previousHash };
}

function buildBatch(
  events: KeaLedgerEvent[],
  entries: readonly KeaLedgerAppend[]
): { events: KeaLedgerEvent[]; appended: KeaLedgerEvent[] } {
  const next = events.map((event) => structuredClone(event));
  const appended: KeaLedgerEvent[] = [];
  for (const entry of entries) {
    const event = buildEvent(next, entry.kind, entry.messageId, entry.data, entry.at);
    next.push(event);
    appended.push(event);
  }
  return { events: next, appended };
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
    const [event] = this.appendBatch([{ kind, messageId, data, at }]);
    if (!event) throw new Error("Kea ledger append produced no event");
    return event;
  }

  appendBatch(entries: readonly KeaLedgerAppend[], guard?: KeaLedgerGuard): KeaLedgerEvent[] {
    if (!entries.length) return [];
    verifyKeaLedger(this.events);
    guard?.(this.events.map((event) => structuredClone(event)));
    const batch = buildBatch(this.events, entries);
    this.events = batch.events;
    return batch.appended.map((event) => structuredClone(event));
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
    const [event] = this.appendBatch([{ kind, messageId, data, at }]);
    if (!event) throw new Error("Kea ledger append produced no event");
    return event;
  }

  appendBatch(entries: readonly KeaLedgerAppend[], guard?: KeaLedgerGuard): KeaLedgerEvent[] {
    if (!entries.length) return [];
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
      guard?.(events.map((event) => structuredClone(event)));
      const batch = buildBatch(events, entries);
      const next = batch.events.map((item) => canonicalJson(item)).join("\n");
      writeFileSync(temp, `${next}\n`, { encoding: "utf8", mode: 0o600 });
      const tempFd = openSync(temp, "r");
      try {
        fsyncSync(tempFd);
      } finally {
        closeSync(tempFd);
      }
      renameSync(temp, this.path);
      try {
        chmodSync(directory, 0o700);
        chmodSync(this.path, 0o600);
      } catch {
        /* best effort on filesystems without POSIX modes */
      }
      return batch.appended.map((event) => structuredClone(event));
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
