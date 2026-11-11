// Codex: PreToolUse hook group in hooks.json. Same entry contract as Claude Code; Codex tools are Bash and apply_patch (Edit/Write).
import { applyPreToolUse, hasOurPreToolUse, parseJsonObject, removePreToolUse, serializeLike } from "./claude.js";

export const CODEX_MATCHER = "Bash|Edit|Write";

/** `[newText, changed]`; unchanged input is returned byte for byte. Throws on unparsable or unexpectedly shaped JSON. */
export function computeCodexUpdate(hooksJson: string, hookCommand: string): [string, boolean] {
  const config = parseJsonObject(hooksJson);
  return applyPreToolUse(config, CODEX_MATCHER, hookCommand) ? [serializeLike(hooksJson, config), true] : [hooksJson, false];
}

export function computeCodexRemoval(hooksJson: string): [string, boolean] {
  const config = parseJsonObject(hooksJson);
  return removePreToolUse(config) ? [serializeLike(hooksJson, config), true] : [hooksJson, false];
}

export function codexInstalled(hooksJson: string): boolean {
  try {
    return hasOurPreToolUse(parseJsonObject(hooksJson));
  } catch {
    return false;
  }
}
