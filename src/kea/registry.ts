import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { canonicalJson, hashCanonical } from "./canonical.js";
import { defaultKeaRoot } from "./paths.js";
import type { KeaCodecManifest } from "./types.js";

export type KeaCodecManifestInput = Omit<KeaCodecManifest, "integrityHash">;

function manifestCore(manifest: KeaCodecManifestInput | KeaCodecManifest) {
  const { integrityHash: _ignored, ...core } = manifest as KeaCodecManifest;
  return core;
}

export function finalizeManifest(input: KeaCodecManifestInput): KeaCodecManifest {
  if (!input.codecId || !input.codecVersion || !input.decoderId || !input.decoderVersion) {
    throw new Error("Kea codec and decoder identifiers are required");
  }
  if (!Number.isInteger(input.maxPayloadBytes) || input.maxPayloadBytes <= 0) {
    throw new Error("Kea maxPayloadBytes must be a positive integer");
  }
  const core = manifestCore(input);
  return { ...core, integrityHash: hashCanonical(core) };
}

export function verifyManifest(manifest: KeaCodecManifest): boolean {
  return hashCanonical(manifestCore(manifest)) === manifest.integrityHash;
}

export interface KeaRegistryLike {
  register(input: KeaCodecManifestInput): KeaCodecManifest;
  get(codecId: string, codecVersion: string): KeaCodecManifest | null;
  list(): KeaCodecManifest[];
}

export class MemoryKeaRegistry implements KeaRegistryLike {
  protected manifests = new Map<string, KeaCodecManifest>();

  constructor(initial: KeaCodecManifest[] = []) {
    for (const manifest of initial) {
      if (!verifyManifest(manifest)) throw new Error(`Invalid Kea manifest ${manifest.codecId}`);
      this.manifests.set(this.key(manifest.codecId, manifest.codecVersion), structuredClone(manifest));
    }
  }

  protected key(codecId: string, codecVersion: string): string {
    return `${codecId}@${codecVersion}`;
  }

  register(input: KeaCodecManifestInput): KeaCodecManifest {
    const manifest = finalizeManifest(input);
    const key = this.key(manifest.codecId, manifest.codecVersion);
    const existing = this.manifests.get(key);
    if (existing && existing.integrityHash !== manifest.integrityHash) {
      throw new Error(`Kea manifest ${key} is immutable; register a new version`);
    }
    if (!existing) this.manifests.set(key, structuredClone(manifest));
    return structuredClone(existing || manifest);
  }

  get(codecId: string, codecVersion: string): KeaCodecManifest | null {
    const manifest = this.manifests.get(this.key(codecId, codecVersion));
    return manifest ? structuredClone(manifest) : null;
  }

  list(): KeaCodecManifest[] {
    return [...this.manifests.values()]
      .map((manifest) => structuredClone(manifest))
      .sort((a, b) =>
        `${a.codecId}@${a.codecVersion}`.localeCompare(`${b.codecId}@${b.codecVersion}`)
      );
  }
}

export class FileKeaRegistry extends MemoryKeaRegistry {
  readonly path: string;

  constructor(root = defaultKeaRoot()) {
    const path = join(root, "registry.json");
    let initial: KeaCodecManifest[] = [];
    if (existsSync(path)) {
      const parsed = JSON.parse(readFileSync(path, "utf8")) as {
        schemaVersion?: string;
        manifests?: KeaCodecManifest[];
      };
      initial = Array.isArray(parsed.manifests) ? parsed.manifests : [];
    }
    super(initial);
    this.path = path;
  }

  override register(input: KeaCodecManifestInput): KeaCodecManifest {
    const before = this.list().length;
    const manifest = super.register(input);
    if (this.list().length !== before) this.persist();
    return manifest;
  }

  private persist(): void {
    const directory = dirname(this.path);
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const temp = `${this.path}.tmp-${process.pid}`;
    const value = {
      schemaVersion: "1.0.0",
      manifests: this.list(),
    };
    writeFileSync(temp, `${canonicalJson(value)}\n`, { encoding: "utf8", mode: 0o600 });
    renameSync(temp, this.path);
    try {
      chmodSync(directory, 0o700);
      chmodSync(this.path, 0o600);
    } catch {
      /* best effort on filesystems without POSIX modes */
    }
  }
}
