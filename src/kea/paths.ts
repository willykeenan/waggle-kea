import { homedir } from "node:os";
import { join } from "node:path";

export function defaultKeaRoot(): string {
  return join(homedir(), ".waggle-kea", "kea");
}
