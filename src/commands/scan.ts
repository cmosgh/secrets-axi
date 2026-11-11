// Bounded repository scan for Secret Files (home view, detection). Names only.
import { readdirSync, statSync, type Dirent } from "node:fs";
import { basename, join, relative } from "node:path";
import { basenamePatterns, matchesAny, type Policy } from "../policy.js";

const SKIP = new Set(["node_modules", ".git", "dist", "build", ".next", ".nuxt", "coverage", ".turbo", ".cache", "vendor", "target", ".venv", "venv", "__pycache__"]);
const MAX_ENTRIES = 5000;
const MAX_DEPTH = 4;
const DEADLINE_MS = 400;

export interface ScanResult {
  /** Relative paths of Secret Files below cwd, outside worktree copies. */
  files: string[];
  /** Secret Files inside agent worktrees, one entry per path within a worktree, with the number of worktrees holding it. */
  worktrees: WorktreeCopies[];
  capped: boolean;
}

export interface WorktreeCopies {
  /** Path inside the worktree (`.env`). */
  path: string;
  /** The worktree container relative to cwd (`.claude/worktrees`). */
  root: string;
  count: number;
}

/** Containers of agent worktrees: copies of the repository whose Secret Files are the same ones again. */
function isWorktreeRoot(parent: string, name: string): boolean {
  return name === ".worktrees" || (name === "worktrees" && parent === ".claude");
}

export function scanSecretFiles(cwd: string, policy: Policy): ScanResult {
  const patterns = basenamePatterns(policy);
  const files: string[] = [];
  const copies = new Map<string, WorktreeCopies>();
  let seen = 0;
  let capped = false;
  const deadline = Date.now() + DEADLINE_MS;
  const walk = (dir: string, depth: number, worktree?: { root: string; dir: string }): void => {
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
        if (SKIP.has(entry.name)) continue;
        if (!worktree && isWorktreeRoot(basename(dir), entry.name)) {
          const root = relative(cwd, path);
          for (const wt of listDirs(path)) walk(join(path, wt), 0, { root, dir: join(path, wt) });
        } else if (depth < MAX_DEPTH) walk(path, depth + 1, worktree);
      } else if (entry.isFile() && matchesAny(entry.name, patterns) && !matchesAny(entry.name, policy.secretFileExceptions)) {
        if (worktree) {
          const inside = relative(worktree.dir, path);
          const key = `${worktree.root}\0${inside}`;
          const hit = copies.get(key) ?? { path: inside, root: worktree.root, count: 0 };
          hit.count++;
          copies.set(key, hit);
        } else {
          files.push(relative(cwd, path));
        }
      }
    }
  };
  walk(cwd, 0);
  const worktrees = [...copies.values()].sort((a, b) => b.count - a.count || a.path.localeCompare(b.path));
  return { files: files.sort(), worktrees, capped };
}

function listDirs(dir: string): string[] {
  try {
    return readdirSync(dir, { withFileTypes: true })
      .filter((e) => e.isDirectory())
      .map((e) => e.name)
      .sort();
  } catch {
    return [];
  }
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
