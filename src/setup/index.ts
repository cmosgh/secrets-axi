// Installers for the Guard (PreToolUse hooks + deny rules) and the SDK-managed SessionStart hooks.
import { existsSync, mkdirSync, readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import {
  extractNpmShimScriptPath,
  installSessionStartHooks,
  resolvePortableHookCommand,
  sessionStartHookStatus,
  shouldInstallHooksForNodeAxiExecPath,
  uninstallSessionStartHooks,
  type SessionStartHookStatus,
} from "axi-sdk-js";
import { axiError } from "../errors.js";
import { MARKER } from "../meta.js";
import { claudeDenyRules, claudeStatus, computeClaudeRemoval, computeClaudeUpdate } from "./claude.js";
import { codexInstalled, computeCodexRemoval, computeCodexUpdate } from "./codex.js";

export { claudeDenyRules, computeClaudeRemoval, computeClaudeUpdate } from "./claude.js";
export { computeCodexRemoval, computeCodexUpdate } from "./codex.js";

export type Scope = "user" | "project";

export interface GuardOptions {
  scope: Scope;
  cwd: string;
  /** Defaults to the real home directory; tests point it at a temp dir. */
  homeDir?: string;
}

const IDENTITY = { marker: MARKER, binaryNames: ["secrets-axi"], distEntrypoints: ["dist/bin/secrets-axi.js"] };

// --- hook command ---

function portableContext() {
  const pathEntries = (process.env["PATH"] ?? "").split(delimiter).filter(Boolean);
  return {
    pathEntries,
    pathExtensions: process.platform === "win32" ? ["", ...(process.env["PATHEXT"] ?? ".COM;.EXE;.BAT;.CMD").split(";")] : [""],
    resolveRealPath: (p: string) => {
      try {
        return statSync(p).isFile() ? realpathSync(p) : undefined;
      } catch {
        return undefined;
      }
    },
    resolveShimTarget: (shim: string) => {
      try {
        const rel = extractNpmShimScriptPath(readFileSync(shim, "utf8"));
        return rel ? realpathSync(resolve(dirname(shim), rel)) : undefined;
      } catch {
        return undefined;
      }
    },
  };
}

function quoteArg(p: string): string {
  return /^[\w./:@+\\-]+$/.test(p) ? p : `"${p.replace(/(["\\$`])/g, "\\$1")}"`;
}

/**
 * `secrets-axi hook` for a global install, else `node <abs entrypoint> hook`; undefined when the
 * running binary is not an installed secrets-axi (npx, tsx, tests), where a hook path would rot.
 */
export function resolveHookCommand(execPath: string | undefined = process.argv[1]): string | undefined {
  if (!execPath) return undefined;
  const abs = resolve(execPath);
  if (!shouldInstallHooksForNodeAxiExecPath(abs, IDENTITY)) return undefined;
  const command = resolvePortableHookCommand(abs, IDENTITY.binaryNames, MARKER, portableContext());
  return command === "secrets-axi" ? "secrets-axi hook" : `node ${quoteArg(command)} hook`;
}

// --- Guard files ---

function paths({ scope, cwd, homeDir }: GuardOptions): { claude: string; codex: string } {
  const root = scope === "project" ? resolve(cwd) : (homeDir ?? homedir());
  return { claude: join(root, ".claude", "settings.json"), codex: join(root, ".codex", "hooks.json") };
}

function readText(path: string): string {
  return existsSync(path) ? readFileSync(path, "utf8") : "";
}

function write(path: string, text: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, text, "utf8");
}

/** Compute both files first so an unparsable one fails before anything is written. */
function applyBoth(
  options: GuardOptions,
  claude: (text: string) => [string, boolean],
  codex: (text: string) => [string, boolean],
): { claude: { path: string; changed: boolean }; codex: { path: string; changed: boolean } } {
  const p = paths(options);
  const plan = [
    { path: p.claude, run: claude },
    { path: p.codex, run: codex },
  ].map(({ path, run }) => {
    try {
      const [text, changed] = run(readText(path));
      return { path, text, changed };
    } catch (error) {
      throw axiError(`${path}: ${error instanceof Error ? error.message : String(error)}`, "SETUP_FAILED", [
        "Fix or move the file, then run `secrets-axi setup hooks` again (nothing was written)",
      ]);
    }
  });
  for (const step of plan) if (step.changed) write(step.path, step.text);
  const [c, x] = plan as [(typeof plan)[number], (typeof plan)[number]];
  return { claude: { path: c.path, changed: c.changed }, codex: { path: x.path, changed: x.changed } };
}

export function installGuard(options: GuardOptions & { hookCommand: string }) {
  return applyBoth(
    options,
    (text) => computeClaudeUpdate(text, options.hookCommand, claudeDenyRules()),
    (text) => computeCodexUpdate(text, options.hookCommand),
  );
}

export function uninstallGuard(options: GuardOptions) {
  return applyBoth(
    options,
    (text) => computeClaudeRemoval(text, claudeDenyRules()),
    (text) => computeCodexRemoval(text),
  );
}

export interface GuardStatus {
  claude: { installed: boolean; path: string; denyRules: number };
  codex: { installed: boolean; path: string };
}

export function guardStatus(options: GuardOptions): GuardStatus {
  const p = paths(options);
  const claude = claudeStatus(readText(p.claude), claudeDenyRules());
  return { claude: { ...claude, path: p.claude }, codex: { installed: codexInstalled(readText(p.codex)), path: p.codex } };
}

// --- SessionStart (SDK) ---

export interface SessionStartOptions extends GuardOptions {
  /** Test seam; the SDK defaults to process.argv[1]. */
  execPath?: string;
}

function sdkOptions({ scope, cwd, homeDir, execPath }: SessionStartOptions) {
  return { ...IDENTITY, scope, projectDir: cwd, ...(homeDir ? { homeDir } : {}), ...(execPath ? { execPath } : {}) };
}

export function installSessionStart(options: SessionStartOptions): string[] {
  const errors: string[] = [];
  installSessionStartHooks({ ...sdkOptions(options), onError: (m) => errors.push(m) });
  return errors;
}

export function uninstallSessionStart(options: SessionStartOptions): string[] {
  const errors: string[] = [];
  uninstallSessionStartHooks({ ...sdkOptions(options), onError: (m) => errors.push(m) });
  return errors;
}

export function sessionStartStatus(options: SessionStartOptions): SessionStartHookStatus {
  return sessionStartHookStatus(sdkOptions(options));
}

/** Agents with a live SessionStart entry; Codex counts only with its hooks feature on. */
export function sessionStartAgents(status: SessionStartHookStatus): string[] {
  return [
    status.claude.installed && "Claude Code",
    status.codex.installed && status.codex.userFeatureEnabled && "Codex",
    status.opencode.installed && "OpenCode",
  ].filter((a): a is string => typeof a === "string");
}

/** Contents of every file setup may write; equal before and after = nothing changed. */
export function configSnapshot(options: SessionStartOptions): string {
  const g = paths(options);
  const s = sessionStartStatus(options);
  return [g.claude, g.codex, s.codex.userFeaturePath, s.opencode.path].map(readText).join("\0");
}
