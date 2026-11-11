// Bounded repository scan for Secret Files (home view, detection). Names only.
import { readdirSync, statSync, type Dirent } from "node:fs";
import { join, relative } from "node:path";
import { basenamePatterns, matchesAny, type Policy } from "../policy.js";

const SKIP = new Set(["node_modules", ".git", "dist", "build", ".next", ".nuxt", "coverage", ".turbo", ".cache", "vendor", "target", ".venv", "venv", "__pycache__"]);
const MAX_ENTRIES = 5000;
const MAX_DEPTH = 4;
const DEADLINE_MS = 400;

export interface ScanResult {
  /** Relative paths of Secret Files below cwd. */
  files: string[];
  capped: boolean;
}

export function scanSecretFiles(cwd: string, policy: Policy): ScanResult {
  const patterns = basenamePatterns(policy);
  const files: string[] = [];
  let seen = 0;
  let capped = false;
  const deadline = Date.now() + DEADLINE_MS;
  const walk = (dir: string, depth: number): void => {
    if (capped) return;
    let entries: Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (++seen > MAX_ENTRIES || Date.now() > deadline) {
        capped = true;
        return;
      }
      const path = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP.has(entry.name) && depth < MAX_DEPTH) walk(path, depth + 1);
      } else if (entry.isFile() && matchesAny(entry.name, patterns) && !matchesAny(entry.name, policy.secretFileExceptions)) {
        files.push(relative(cwd, path));
      }
    }
  };
  walk(cwd, 0);
  return { files: files.sort(), capped };
}

/** Env-shaped files directly in cwd (`.env`, `.env.local`, ...), for detection and the "not loaded" list. */
export function findEnvFiles(cwd: string, policy: Policy): string[] {
  let names: string[];
  try {
    names = readdirSync(cwd);
  } catch {
    return [];
  }
  return names
    .filter((n) => /^\.env(\..+)?$/.test(n) && !matchesAny(n, policy.secretFileExceptions))
    .filter((n) => {
      try {
        return statSync(join(cwd, n)).isFile();
      } catch {
        return false;
      }
    })
    .sort();
}
