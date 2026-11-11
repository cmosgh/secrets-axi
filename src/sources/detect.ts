// Secret Source detection: from what is on disk, first match wins (PLAN.md). Never reads values here.
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Policy } from "../policy.js";

export type SourceKind = "op" | "doppler" | "infisical" | "dotenvx" | "dotenv" | "none";

export interface Detected {
  kind: SourceKind;
  /** Why this source: the file or marker that decided it. */
  reason: string;
  /** Env files that exist, in policy order. */
  envFiles: string[];
  /** Env-shaped files present but not in `envFiles`. */
  otherEnvFiles: string[];
  /** Sources recognised but not supported in this version. */
  unsupported?: string;
}

/** Supported in this version; the others are detection stubs. */
export const SUPPORTED: ReadonlySet<SourceKind> = new Set<SourceKind>(["dotenv", "none"]);

export function detectSource(cwd: string, policy: Policy, candidates: readonly string[]): Detected {
  const envFiles = policy.envFiles.filter((f) => existsSync(join(cwd, f)));
  const otherEnvFiles = candidates.filter((f) => !policy.envFiles.includes(f));
  const base = { envFiles, otherEnvFiles };
  const first = envFiles[0];
  if (first && /^\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*["']?op:\/\//m.test(readFileSync(join(cwd, first), "utf8"))) {
    return { ...base, kind: "op", reason: `${first} holds op:// references`, unsupported: "1Password (op inject) - planned; run `op run --env-file` yourself for now" };
  }
  if (existsSync(join(cwd, "doppler.yaml"))) return { ...base, kind: "doppler", reason: "doppler.yaml", unsupported: "Doppler - planned; `doppler run` for now" };
  if (existsSync(join(cwd, ".infisical.json"))) return { ...base, kind: "infisical", reason: ".infisical.json", unsupported: "Infisical - planned; `infisical run` for now" };
  if (existsSync(join(cwd, ".env.keys"))) return { ...base, kind: "dotenvx", reason: ".env.keys (dotenvx-encrypted)", unsupported: "dotenvx - planned; `dotenvx run` for now" };
  if (envFiles.length > 0) return { ...base, kind: "dotenv", reason: envFiles.join(", ") };
  return { ...base, kind: "none", reason: `no ${policy.envFiles.join(" or ")} in ${cwd === process.cwd() ? "the working directory" : cwd}` };
}
