import { MemoryKeaLedger } from "../kea/ledger.js";
import { MemoryKeaRegistry } from "../kea/registry.js";
import { KeaService } from "../kea/service.js";
import { keaWaggleV0Decoder, waggleV0Manifest } from "./codec.js";

export function createWaggleV0FixtureKea(options?: { clock?: () => string }) {
  const registry = new MemoryKeaRegistry();
  registry.register(waggleV0Manifest());
  const ledger = new MemoryKeaLedger();
  const service = new KeaService({
    registry,
    ledger,
    fixtureOnly: true,
    maxUndecodableBytes: 0,
    clock: options?.clock,
  });
  service.registerDecoder(keaWaggleV0Decoder());
  return { service, registry, ledger };
}
