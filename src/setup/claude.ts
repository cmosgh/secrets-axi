// Claude Code: PreToolUse hook group plus permissions.deny rules in settings.json. Pure over file text.
import { BUILTIN } from "../policy.js";

type Json = Record<string, unknown>;

export const PRE_TOOL_USE_MATCHER = "Read|Edit|Write|MultiEdit|NotebookEdit|Grep|Bash";
export const HOOK_TIMEOUT_SECONDS = 5;

/** Our entry is a command that runs `secrets-axi ... hook`; every other hook is left alone. */
export function isOurHookCommand(command: unknown): boolean {
  return typeof command === "string" && /secrets-axi\S*\s+hook(?:\s|$)/.test(command);
}

/**
 * Hard-layer deny rules for the built-in Secret Files: basename patterns match at any depth,
 * `~/` patterns are taken as written; path patterns with other shapes are left to the hook.
 */
/** Deny rules have no exceptions, so `.env.*` would also hide `.env.example`: the hard layer enumerates the usual suffixes instead. */
const ENUMERATED: Record<string, string[]> = {
  ".env.*": ["local", "development", "dev", "production", "prod", "staging", "stage", "test", "testing", "ci", "preview", "secret", "secrets", "private", "local.*"].map((s) => `.env.${s}`),
  ".secrets.*": ["local", "json", "yaml", "yml", "env", "toml"].map((s) => `.secrets.${s}`),
};

export function claudeDenyRules(patterns: readonly string[] = BUILTIN.secretFiles): string[] {
  const rules = patterns.flatMap((p) => {
    if (p.startsWith("~/")) return [`Read(${p})`];
    if (p.includes("/")) return [];
    return (ENUMERATED[p] ?? [p]).map((name) => `Read(./**/${name})`);
  });
  return [...new Set(rules)];
}

// --- shared JSON file handling (Codex reuses it) ---

export function parseJsonObject(text: string): Json {
  if (text.trim() === "") return {};
  const value: unknown = JSON.parse(text);
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("top level is not a JSON object");
  return value as Json;
}

/** Re-serialise with the file's own indent and trailing newline (2 spaces + newline for a new file). */
export function serializeLike(original: string, value: Json): string {
  const indent = original.match(/^([ \t]+)\S/m)?.[1] ?? "  ";
  const newline = original === "" || original.endsWith("\n") ? "\n" : "";
  return `${JSON.stringify(value, null, indent)}${newline}`;
}

interface HookEntry extends Json {
  type?: unknown;
  command?: unknown;
  timeout?: unknown;
}
interface HookGroup extends Json {
  matcher?: unknown;
  hooks?: unknown;
}

function asObject(value: unknown, what: string): Json {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${what} is not an object`);
  return value as Json;
}

function asArray(value: unknown, what: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${what} is not an array`);
  return value;
}

/** Add or refresh our PreToolUse entry in place; later duplicates are dropped. Returns whether anything changed. */
export function applyPreToolUse(settings: Json, matcher: string, command: string): boolean {
  let changed = false;
  if (settings["hooks"] === undefined) {
    settings["hooks"] = {};
    changed = true;
  }
  const hooks = asObject(settings["hooks"], "hooks");
  if (hooks["PreToolUse"] === undefined) {
    hooks["PreToolUse"] = [];
    changed = true;
  }
  const groups = asArray(hooks["PreToolUse"], "hooks.PreToolUse") as HookGroup[];

  let found = false;
  const kept: unknown[] = [];
  for (const group of groups) {
    if (group === null || typeof group !== "object" || !Array.isArray(group.hooks)) {
      kept.push(group);
      continue;
    }
    const entries = group.hooks as HookEntry[];
    const before = entries.length;
    let hadOurs = false;
    const filtered = entries.filter((hook) => {
      if (!isOurHookCommand(hook?.command)) return true;
      hadOurs = true;
      if (found) return false;
      found = true;
      if (hook.command !== command || hook.type !== "command" || hook.timeout !== HOOK_TIMEOUT_SECONDS) {
        hook.command = command;
        hook.type = "command";
        hook.timeout = HOOK_TIMEOUT_SECONDS;
        changed = true;
      }
      return true;
    });
    group.hooks = filtered;
    if (filtered.length !== before) changed = true;
    // A group holding only our hook follows our matcher; shared groups keep the user's.
    if (hadOurs && filtered.length === 1 && group.matcher !== matcher) {
      group.matcher = matcher;
      changed = true;
    }
    if (filtered.length > 0 || before === 0) kept.push(group);
  }
  if (!found) {
    kept.push({ matcher, hooks: [{ type: "command", command, timeout: HOOK_TIMEOUT_SECONDS }] });
    changed = true;
  }
  if (kept.length !== groups.length || changed) hooks["PreToolUse"] = kept;
  return changed;
}

/** Remove only our PreToolUse entries; empty groups, then an empty PreToolUse and `hooks`, are dropped. */
export function removePreToolUse(settings: Json): boolean {
  const hooks = settings["hooks"];
  if (hooks === null || typeof hooks !== "object" || Array.isArray(hooks)) return false;
  const h = hooks as Json;
  if (!Array.isArray(h["PreToolUse"])) return false;
  let changed = false;
  const kept: unknown[] = [];
  for (const group of h["PreToolUse"] as HookGroup[]) {
    if (group === null || typeof group !== "object" || !Array.isArray(group.hooks)) {
      kept.push(group);
      continue;
    }
    const remaining = (group.hooks as HookEntry[]).filter((hook) => !isOurHookCommand(hook?.command));
    if (remaining.length === group.hooks.length) {
      kept.push(group);
      continue;
    }
    changed = true;
    if (remaining.length > 0) kept.push({ ...group, hooks: remaining });
  }
  if (!changed) return false;
  if (kept.length > 0) h["PreToolUse"] = kept;
  else delete h["PreToolUse"];
  if (Object.keys(h).length === 0) delete settings["hooks"];
  return true;
}

export function hasOurPreToolUse(settings: Json): boolean {
  const groups = (settings["hooks"] as Json | undefined)?.["PreToolUse"];
  if (!Array.isArray(groups)) return false;
  return groups.some((g: HookGroup) => Array.isArray(g?.hooks) && (g.hooks as HookEntry[]).some((h) => isOurHookCommand(h?.command)));
}

/** `[newText, changed]`; unchanged input is returned byte for byte. Throws on unparsable or unexpectedly shaped JSON. */
export function computeClaudeUpdate(settingsJson: string, hookCommand: string, denyRules: string[]): [string, boolean] {
  const settings = parseJsonObject(settingsJson);
  let changed = applyPreToolUse(settings, PRE_TOOL_USE_MATCHER, hookCommand);

  if (denyRules.length > 0) {
    if (settings["permissions"] === undefined) {
      settings["permissions"] = {};
      changed = true;
    }
    const permissions = asObject(settings["permissions"], "permissions");
    if (permissions["deny"] === undefined) {
      permissions["deny"] = [];
      changed = true;
    }
    const deny = asArray(permissions["deny"], "permissions.deny");
    for (const rule of denyRules) {
      if (!deny.includes(rule)) {
        deny.push(rule);
        changed = true;
      }
    }
  }
  return changed ? [serializeLike(settingsJson, settings), true] : [settingsJson, false];
}

/** Removes our hook entries and exactly the deny rules in `denyRules` (exact string match). */
export function computeClaudeRemoval(settingsJson: string, denyRules: string[]): [string, boolean] {
  const settings = parseJsonObject(settingsJson);
  let changed = removePreToolUse(settings);

  const permissions = settings["permissions"];
  if (permissions !== null && typeof permissions === "object" && !Array.isArray(permissions)) {
    const p = permissions as Json;
    if (Array.isArray(p["deny"])) {
      const remaining = (p["deny"] as unknown[]).filter((rule) => !(typeof rule === "string" && denyRules.includes(rule)));
      if (remaining.length !== (p["deny"] as unknown[]).length) {
        changed = true;
        if (remaining.length > 0) p["deny"] = remaining;
        else delete p["deny"];
        if (Object.keys(p).length === 0) delete settings["permissions"];
      }
    }
  }
  return changed ? [serializeLike(settingsJson, settings), true] : [settingsJson, false];
}

/** Our hook entry present, and how many of `denyRules` are in permissions.deny. */
export function claudeStatus(settingsJson: string, denyRules: string[]): { installed: boolean; denyRules: number } {
  let settings: Json;
  try {
    settings = parseJsonObject(settingsJson);
  } catch {
    return { installed: false, denyRules: 0 };
  }
  const deny = (settings["permissions"] as Json | undefined)?.["deny"];
  const present = Array.isArray(deny) ? denyRules.filter((r) => deny.includes(r)).length : 0;
  return { installed: hasOurPreToolUse(settings), denyRules: present };
}
