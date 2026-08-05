import { pathToFileURL } from "node:url";
import { defaultKeaRoot } from "./paths.js";
import { FileKeaLedger, verifyKeaLedger } from "./ledger.js";
import { FileKeaRegistry } from "./registry.js";
import { KeaService } from "./service.js";
import { createFixtureFileKea } from "./factory.js";
import { createFixtureMessage } from "./fixtures.js";
import { runKeaEvaluation } from "./evaluation.js";
import { startKeaServer } from "./server.js";

function valueAfter(args: string[], flag: string): string | undefined {
  const index = args.indexOf(flag);
  return index >= 0 ? args[index + 1] : undefined;
}

function print(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

function help(): string {
  return [
    "Kea · separate decoder and audit system",
    "",
    "Usage:",
    "  kea status [--root PATH]              read-only registry and ledger status",
    "  kea registry [--root PATH]            list codec/decoder manifests",
    "  kea replay MESSAGE_ID [--root PATH]   replay one causal record",
    "  kea evaluate                          run the deterministic fixture harness",
    "  kea fixture [JSON] [--root PATH]      append one sanitized fixture",
    "  kea serve [--port N] [--root PATH] [--allow-fixtures]",
    "",
    "This build is fixture-only. These commands never start models or capabilities.",
  ].join("\n");
}

export async function runKeaCli(argv = process.argv.slice(2)): Promise<number> {
  const command = argv[0] || "status";
  const root = valueAfter(argv, "--root") || process.env.KEA_ROOT || defaultKeaRoot();

  if (command === "help" || command === "--help" || command === "-h") {
    process.stdout.write(`${help()}\n`);
    return 0;
  }
  if (command === "evaluate") {
    const report = runKeaEvaluation();
    print(report);
    return report.passed ? 0 : 1;
  }
  if (command === "status") {
    const registry = new FileKeaRegistry(root);
    const ledger = new FileKeaLedger(root);
    const events = ledger.read();
    const chain = verifyKeaLedger(events);
    print({
      product: "Kea",
      mode: "fixture-only",
      root,
      registryEntries: registry.list().length,
      ledgerEvents: events.length,
      messages: events.filter((event) => event.kind === "message").length,
      interpretations: events.filter((event) => event.kind === "interpretation").length,
      corrections: events.filter((event) => event.kind === "correction").length,
      chainVerified: chain.ok,
      liveTrafficAccepted: false,
      authorityExecution: false,
    });
    return 0;
  }
  if (command === "registry") {
    print({ manifests: new FileKeaRegistry(root).list() });
    return 0;
  }
  if (command === "replay") {
    const messageId = argv[1];
    if (!messageId || messageId.startsWith("--")) throw new Error("kea replay requires MESSAGE_ID");
    const registry = new FileKeaRegistry(root);
    const ledger = new FileKeaLedger(root);
    const service = new KeaService({ registry, ledger, fixtureOnly: true });
    print(service.replay(messageId));
    return 0;
  }
  if (command === "fixture") {
    const raw = argv[1] && !argv[1].startsWith("--") ? argv[1] : undefined;
    const payload = raw ? (JSON.parse(raw) as unknown) : undefined;
    if (payload !== undefined && (!payload || typeof payload !== "object" || Array.isArray(payload))) {
      throw new Error("Fixture payload must be a JSON object");
    }
    const { service } = createFixtureFileKea(root);
    print(
      service.ingest(
        createFixtureMessage({ payload: payload as Record<string, unknown> | undefined })
      )
    );
    return 0;
  }
  if (command === "serve") {
    const portRaw = valueAfter(argv, "--port");
    const port = portRaw ? Number(portRaw) : 7462;
    if (!Number.isInteger(port) || port < 0 || port > 65_535) throw new Error("Invalid port");
    const running = await startKeaServer({
      root,
      port,
      allowFixtureWrites: argv.includes("--allow-fixtures"),
    });
    process.stdout.write(
      `Kea fixture viewer: http://${running.host}:${running.port}\n` +
        `live traffic: disabled · authority execution: disabled\n`
    );
    await new Promise<void>((resolve) => {
      const stop = () => {
        void running.close().finally(resolve);
      };
      process.once("SIGINT", stop);
      process.once("SIGTERM", stop);
    });
    return 0;
  }
  process.stderr.write(`${help()}\n`);
  return 2;
}

const invoked = process.argv[1] ? pathToFileURL(process.argv[1]).href : "";
if (invoked === import.meta.url) {
  runKeaCli().then(
    (code) => {
      process.exitCode = code;
    },
    (error) => {
      process.stderr.write(`Kea error: ${error instanceof Error ? error.message : String(error)}\n`);
      process.exitCode = 1;
    }
  );
}
