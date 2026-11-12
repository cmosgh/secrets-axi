// macOS keychain generic passwords through the `security` CLI: no native dependency; macOS asks the user
// to allow access the first time for items another app created.
import { spawnSync } from "node:child_process";
import { axiError, usageError } from "../errors.js";

export interface KeychainSpec {
  service: string;
  account: string;
  /** Variable the password is injected as. */
  name: string;
}

/** `<service>/<account>=NAME`: the service ends at the first `/`, the name starts after the last `=`. */
export function parseKeychainSpec(raw: string): KeychainSpec {
  const eq = raw.lastIndexOf("=");
  const slash = raw.indexOf("/");
  const name = eq < 0 ? "" : raw.slice(eq + 1);
  if (slash <= 0 || eq < slash + 2 || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
    throw usageError(`--keychain takes <service>/<account>=NAME (got '${raw}')`, ["e.g. --keychain mysql-axi/develop=DB_PASSWORD"]);
  }
  return { service: raw.slice(0, slash), account: raw.slice(slash + 1, eq), name };
}

export interface KeychainOptions {
  /** Test seam: returns the password for a spec, or throws. */
  fetch?: (spec: KeychainSpec) => string;
}

function cliFetch(spec: KeychainSpec): string {
  if (process.platform !== "darwin") {
    throw axiError("--keychain reads the macOS keychain and needs macOS", "SOURCE_ERROR", ["Use --env-file or --aws-secret on this system"]);
  }
  const result = spawnSync("security", ["find-generic-password", "-s", spec.service, "-a", spec.account, "-w"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error) throw axiError(`security CLI not available (${result.error.message})`, "SOURCE_ERROR");
  if (result.status !== 0) {
    // `security` errors name the item, never the password.
    throw axiError(`keychain: no item for service '${spec.service}' account '${spec.account}' (or access was denied)`, "SOURCE_ERROR", [
      "Check the service and account names in Keychain Access",
    ]);
  }
  return result.stdout.replace(/\n$/, "");
}

export function fetchKeychain(specs: readonly KeychainSpec[], options: KeychainOptions = {}): { env: Map<string, string>; from: string[] } {
  const env = new Map<string, string>();
  const fetch = options.fetch ?? cliFetch;
  for (const spec of specs) env.set(spec.name, fetch(spec));
  return { env, from: specs.map((s) => `${s.service}/${s.account}`) };
}
