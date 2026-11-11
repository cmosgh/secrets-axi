import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { envMap, parseEnv } from "../env.js";

export interface LoadedEnv {
  env: Map<string, string>;
  loaded: string[];
  missing: string[];
}

/** Load env files in order; a later file overrides an earlier one. Values stay in memory. */
export function loadEnvFiles(cwd: string, files: readonly string[]): LoadedEnv {
  const env = new Map<string, string>();
  const loaded: string[] = [];
  const missing: string[] = [];
  for (const file of files) {
    const abs = resolve(cwd, file);
    if (!existsSync(abs)) {
      missing.push(file);
      continue;
    }
    for (const [k, v] of envMap(parseEnv(readFileSync(abs, "utf8")))) env.set(k, v);
    loaded.push(file);
  }
  return { env, loaded, missing };
}
