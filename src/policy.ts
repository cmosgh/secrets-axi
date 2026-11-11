// Policy: the lists every Guard and Runner decision comes from. Node builtins only (the hook loads this).
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, isAbsolute, join, resolve } from "node:path";

export interface Policy {
  /** Basename patterns (`.env.*`, `*.pem`) or home paths (`~/.aws/credentials`); `*` and `?` only. */
  secretFiles: string[];
  /** Basenames that are never Secret Files even when a pattern matches. */
  secretFileExceptions: string[];
  /** Command prefixes whose output is a secret: non-flag tokens in order, flags anywhere (`aws ssm get-parameter --with-decryption`). */
  fetchCommands: string[];
  /** Programs that load a Secret File without printing it: `docker --env-file` (only as that flag's value), `dotenvx` (any token). */
  consumers: string[];
  /** Variables whose values a key listing may show. */
  reveal: string[];
  /** Env files a Guarded Run loads, in order. */
  envFiles: string[];
  /** AWS Secrets Manager ids (`prod/db`) or `id=NAME` for string secrets. */
  aws: string[];
}

export type ListKey = keyof Policy;

/** One layer as written in a policy file: every list adds; `remove` is honoured from the user layer only. */
export interface PolicyLayer extends Partial<Policy> {
  remove?: Partial<Policy>;
}

export const LIST_KEYS: readonly ListKey[] = ["secretFiles", "secretFileExceptions", "fetchCommands", "consumers", "reveal", "envFiles", "aws"];

export const BUILTIN: Policy = {
  secretFiles: [
    ".env",
    ".env.*",
    ".envrc",
    ".secrets",
    ".secrets.*",
    "secrets.json",
    "secrets.yaml",
    "secrets.yml",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.keystore",
    "*.jks",
    "id_rsa*",
    "id_dsa*",
    "id_ecdsa*",
    "id_ed25519*",
    "~/.aws/credentials",
    "~/.ssh/id_*",
    "~/.npmrc",
    "~/.netrc",
    "~/.docker/config.json",
    "~/.kube/config",
    "~/.config/gh/hosts.yml",
    "~/.config/secrets-axi/*.secret",
  ],
  secretFileExceptions: [".env.example", ".env.sample", ".env.template", ".env.dist", ".env.schema", ".env.defaults", "*.pub", ".env.d.ts", ".env.ts", ".env.js"],
  fetchCommands: [
    "aws secretsmanager get-secret-value",
    "aws secretsmanager batch-get-secret-value",
    "aws ssm get-parameter --with-decryption",
    "aws ssm get-parameters --with-decryption",
    "aws ssm get-parameters-by-path --with-decryption",
    "aws sts get-session-token",
    "aws configure export-credentials",
    "aws configure get",
    "op read",
    "op item get",
    "op inject",
    "vault kv get",
    "vault read",
    "doppler secrets",
    "doppler secrets download",
    "doppler secrets get",
    "infisical secrets get",
    "infisical export",
    "dotenvx get",
    "dotenvx decrypt",
    "gcloud secrets versions access",
    "az keyvault secret show",
    "gh auth token",
    "security find-generic-password",
    "security find-internet-password",
    "kubectl get secret",
    "docker config inspect",
  ],
  consumers: ["secrets-axi", "docker --env-file", "docker compose --env-file", "podman --env-file", "dotenv -e", "dotenv --file", "dotenvx", "op run --env-file", "direnv allow", "chmod", "ls", "stat", "file", "wc", "rm", "git add", "git rm", "git checkout --", "git restore", "test", "[", "touch", "echo", "printf", "shred", "basename", "dirname", "realpath", "readlink"],
  reveal: ["NODE_ENV", "ENV", "ENVIRONMENT", "APP_ENV", "PORT", "HOST", "HOSTNAME", "LOG_LEVEL", "DEBUG", "TZ", "LANG", "LC_ALL", "CI", "PUBLIC_URL", "BASE_URL", "APP_NAME", "APP_URL", "API_URL", "API_BASE_URL", "VITE_*", "NEXT_PUBLIC_*", "REACT_APP_*", "PUBLIC_*", "EXPO_PUBLIC_*", "NUXT_PUBLIC_*"],
  envFiles: [".env"],
  aws: [],
};

export const USER_POLICY_PATH = join(homedir(), ".config", "secrets-axi", "policy.json");
export const REPO_POLICY_NAME = ".secrets-axi.json";

export interface PolicyLoad {
  policy: Policy;
  /** `builtin`, `user` or `repo` for each entry of each list. */
  origin: Record<ListKey, Map<string, "builtin" | "user" | "repo">>;
  userPath: string;
  repoPath: string | undefined;
  /** Files that exist but could not be parsed; the layer is skipped, never trusted half-read. */
  broken: string[];
}

function readLayer(path: string, broken: string[]): PolicyLayer | undefined {
  if (!existsSync(path)) return undefined;
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not an object");
    return parsed as PolicyLayer;
  } catch {
    broken.push(path);
    return undefined;
  }
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string" && v.length > 0) : [];
}

/** Built-in → user → repository. Repository entries add; only the user layer may remove. `envFiles` is replaced, not added to. */
export function loadPolicy(cwd: string, options: { userPath?: string; home?: string } = {}): PolicyLoad {
  const broken: string[] = [];
  const userPath = options.userPath ?? USER_POLICY_PATH;
  const repoPath = findRepoPolicy(cwd);
  const layers: Array<["user" | "repo", PolicyLayer | undefined]> = [
    ["user", readLayer(userPath, broken)],
    ["repo", repoPath ? readLayer(repoPath, broken) : undefined],
  ];
  const lists = {} as Record<ListKey, string[]>;
  const origin = {} as PolicyLoad["origin"];
  for (const key of LIST_KEYS) {
    lists[key] = [...BUILTIN[key]];
    origin[key] = new Map(BUILTIN[key].map((v) => [v, "builtin" as const]));
  }
  for (const [name, layer] of layers) {
    if (!layer) continue;
    for (const key of LIST_KEYS) {
      const add = strings(layer[key]);
      if (key === "envFiles" && add.length > 0) {
        lists[key] = [];
        origin[key] = new Map();
      }
      for (const v of add) {
        if (!lists[key].includes(v)) lists[key].push(v);
        origin[key].set(v, name);
      }
    }
    if (name === "user" && layer.remove) {
      for (const key of LIST_KEYS) {
        for (const v of strings(layer.remove[key])) {
          lists[key] = lists[key].filter((x) => x !== v);
          origin[key].delete(v);
        }
      }
    }
  }
  return { policy: lists as Policy, origin, userPath, repoPath, broken };
}

/** Nearest `.secrets-axi.json` from `cwd` up to the git root (or filesystem root). */
export function findRepoPolicy(cwd: string): string | undefined {
  let dir = resolve(cwd);
  for (;;) {
    const candidate = join(dir, REPO_POLICY_NAME);
    if (existsSync(candidate)) return candidate;
    if (existsSync(join(dir, ".git"))) return undefined;
    const parent = resolve(dir, "..");
    if (parent === dir) return undefined;
    dir = parent;
  }
}

/** `*` and `?` glob on one path segment (or a whole path when the pattern has `/`). */
export function globToRegExp(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*").replace(/\?/g, "[^/]");
  // A leading `*` needs one character: `*.key` names key files, not a bare `.key` (a jq filter, a dotfile).
  return new RegExp(`^${escaped.startsWith("[^/]*") ? `[^/]+${escaped.slice(5)}` : escaped}$`);
}

/** One concrete name per basename pattern (`.env.*` → `.env.x`), to test whether a glob token could name a Secret File. */
export function sampleNames(policy: Policy): string[] {
  return basenamePatterns(policy).map((p) => p.replace(/^\*/, "x").replace(/\*/g, "x").replace(/\?/g, "x"));
}

export function matchesAny(name: string, patterns: readonly string[]): string | undefined {
  return patterns.find((p) => globToRegExp(p).test(name));
}

/** Expand a leading `~` of a path or pattern. */
export function expandHome(path: string, home: string = homedir()): string {
  return path === "~" ? home : path.startsWith("~/") ? join(home, path.slice(2)) : path;
}

/**
 * Is `path` (absolute, or relative to `cwd`) a Secret File? Returns the matching pattern.
 * Home patterns match the full path; the others match the basename anywhere.
 */
export function secretFilePattern(path: string, policy: Policy, cwd: string, home: string = homedir()): string | undefined {
  const abs = resolve(cwd, expandHome(path, home));
  const name = basename(abs);
  if (matchesAny(name, policy.secretFileExceptions)) return undefined;
  // Path patterns first: they are the more specific match (`~/.ssh/id_*` over `id_rsa*`).
  const byPath = policy.secretFiles.filter((p) => p.includes("/"));
  for (const pattern of byPath) {
    const full = pattern.startsWith("~/") || isAbsolute(pattern) ? expandHome(pattern, home) : resolve(cwd, pattern);
    if (globToRegExp(full).test(abs)) return pattern;
  }
  return policy.secretFiles.find((p) => !p.includes("/") && globToRegExp(p).test(name));
}

export function isRevealKey(key: string, policy: Policy): boolean {
  return matchesAny(key, policy.reveal) !== undefined;
}

/** Basename patterns only (what a Recursive Search can exclude). */
export function basenamePatterns(policy: Policy): string[] {
  return policy.secretFiles.filter((p) => !p.startsWith("~/") && !isAbsolute(p) && !p.includes("/"));
}
