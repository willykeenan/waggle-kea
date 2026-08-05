import { createHash } from "node:crypto";

function normalize(value: unknown, seen: Set<object>): unknown {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Kea canonical JSON rejects non-finite numbers");
    return value;
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) throw new Error("Kea canonical JSON rejects cycles");
    seen.add(value);
    const out = value.map((item) => normalize(item, seen));
    seen.delete(value);
    return out;
  }
  if (typeof value === "object") {
    const object = value as Record<string, unknown>;
    if (seen.has(object)) throw new Error("Kea canonical JSON rejects cycles");
    seen.add(object);
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(object).sort()) {
      const item = object[key];
      if (item === undefined) continue;
      if (typeof item === "function" || typeof item === "symbol" || typeof item === "bigint") {
        throw new Error(`Kea canonical JSON rejects ${typeof item} at ${key}`);
      }
      out[key] = normalize(item, seen);
    }
    seen.delete(object);
    return out;
  }
  throw new Error(`Kea canonical JSON rejects ${typeof value}`);
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(normalize(value, new Set<object>()));
}

export function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

export function hashCanonical(value: unknown): string {
  return sha256(canonicalJson(value));
}

export function canonicalBytes(value: unknown): number {
  return Buffer.byteLength(canonicalJson(value), "utf8");
}

export function contentId(prefix: string, value: unknown): string {
  return `${prefix}_${hashCanonical(value).slice(0, 20)}`;
}
