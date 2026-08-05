import { FileKeaLedger, MemoryKeaLedger } from "./ledger.js";
import { FileKeaRegistry, MemoryKeaRegistry } from "./registry.js";
import { fixtureCodecManifest, fixtureJsonDecoder } from "./fixtures.js";
import { KeaService } from "./service.js";

export function createFixtureMemoryKea(options?: {
  clock?: () => string;
  maxUndecodableBytes?: number;
}): {
  service: KeaService;
  registry: MemoryKeaRegistry;
  ledger: MemoryKeaLedger;
} {
  const registry = new MemoryKeaRegistry();
  registry.register(fixtureCodecManifest());
  const ledger = new MemoryKeaLedger();
  const service = new KeaService({
    registry,
    ledger,
    fixtureOnly: true,
    maxUndecodableBytes: options?.maxUndecodableBytes,
    clock: options?.clock,
  });
  service.registerDecoder(fixtureJsonDecoder());
  return { service, registry, ledger };
}

export function createFixtureFileKea(root: string): {
  service: KeaService;
  registry: FileKeaRegistry;
  ledger: FileKeaLedger;
} {
  const registry = new FileKeaRegistry(root);
  registry.register(fixtureCodecManifest());
  const ledger = new FileKeaLedger(root);
  const service = new KeaService({
    registry,
    ledger,
    fixtureOnly: true,
    maxUndecodableBytes: 0,
  });
  service.registerDecoder(fixtureJsonDecoder());
  return { service, registry, ledger };
}
