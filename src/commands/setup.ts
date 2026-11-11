import { bool, expectPositionals, parseArgs } from "../args.js";
import { axiError, usageError } from "../errors.js";
import { block, helpBlock, out } from "../render.js";
import {
  configSnapshot,
  guardStatus,
  installGuard,
  installSessionStart,
  resolveHookCommand,
  sessionStartAgents,
  sessionStartStatus,
  uninstallGuard,
  uninstallSessionStart,
  type Scope,
} from "../setup/index.js";

export const SETUP_HELP = `usage: secrets-axi setup <hooks|status|uninstall> [--project]
Manage the Guard for Claude Code and Codex: a PreToolUse hook that denies secret reads with the right command instead, Read deny rules for the built-in Secret Files (Claude Code), and the SessionStart overview.
flags:
  --project (install into the current repository's agent config instead of your user config)
notes:
  Only secrets-axi's own entries are touched; other hooks and deny rules in the same files are kept
  Hooks are installed from an installed binary (npm i -g secrets-axi), not npx
  Sandbox denyRead is recommended in \`status\` and never written
examples[3]:
  secrets-axi setup hooks
  secrets-axi setup hooks --project
  secrets-axi setup status
`;

export interface SetupContext {
  cwd: string;
  /** Test seams: agent config root and the binary path the hook command is derived from. */
  homeDir?: string;
  execPath?: string;
}

const SANDBOX_NOTE = "recommended: sandbox.filesystem.denyRead for ~/.aws, ~/.ssh (not written by secrets-axi)";

function sessionStartLine(agents: string[]): string {
  if (agents.length === 0) return "not installed";
  return agents.length === 3 ? "installed" : `partial (${agents.join("; ")})`;
}

export async function setupCommand(args: string[], ctx: SetupContext): Promise<string> {
  const [sub, ...rest] = args;
  if (sub !== "hooks" && sub !== "status" && sub !== "uninstall") {
    throw usageError(sub ? `unknown setup action '${sub}'` : "missing setup action", [
      "Run `secrets-axi setup hooks` to install, `secrets-axi setup status` to inspect, `secrets-axi setup uninstall` to remove",
    ]);
  }
  const command = `secrets-axi setup ${sub}`;
  const parsed = parseArgs(rest, [{ name: "--project", boolean: true }], command);
  expectPositionals(parsed, 0, `${command} [--project]`);
  const scope: Scope = bool(parsed, "--project") ? "project" : "user";
  const flagHint = scope === "project" ? " --project" : "";
  const options = { scope, cwd: ctx.cwd, ...(ctx.homeDir ? { homeDir: ctx.homeDir } : {}), ...(ctx.execPath ? { execPath: ctx.execPath } : {}) };

  const view = () => {
    const guard = guardStatus(options);
    const session = sessionStartAgents(sessionStartStatus(options));
    return {
      guard,
      session,
      lines: {
        scope,
        claude_code: guard.claude.installed ? `installed (${guard.claude.denyRules} deny rules)` : "not installed",
        codex: guard.codex.installed ? "installed" : "not installed",
        session_start: sessionStartLine(session),
      },
    };
  };

  if (sub === "status") {
    const { guard, session, lines } = view();
    const missing = !guard.claude.installed || !guard.codex.installed || session.length < 3;
    return out(
      block({ guard: lines, sandbox: SANDBOX_NOTE }),
      helpBlock(missing ? [`Run \`secrets-axi setup hooks${flagHint}\` to install the missing ones`] : []),
    );
  }

  if (sub === "uninstall") {
    const before = configSnapshot(options);
    uninstallGuard(options);
    const errors = uninstallSessionStart(options);
    const { guard, session } = view();
    if (errors.length > 0 || guard.claude.installed || guard.codex.installed || session.length > 0) {
      throw axiError("hooks not fully removed", "SETUP_FAILED", errors.length > 0 ? errors : ["Remove the remaining secrets-axi entries by hand"]);
    }
    return block({ guard: { scope, status: configSnapshot(options) === before ? "not installed (no-op)" : "removed" } });
  }

  const hookCommand = resolveHookCommand(ctx.execPath);
  if (!hookCommand) {
    throw axiError("no hooks were installed: not running from an installed secrets-axi binary", "SETUP_FAILED", [
      "Hooks are only installed from an installed binary, not npx: run `npm i -g secrets-axi`, then `secrets-axi setup hooks`",
    ]);
  }
  const before = configSnapshot(options);
  installGuard({ ...options, hookCommand });
  const errors = installSessionStart(options);
  const { guard, session, lines } = view();
  if (errors.length > 0 || !guard.claude.installed || !guard.codex.installed || session.length < 3) {
    throw axiError(`hooks only partly installed (${Object.values({ claude_code: lines.claude_code, codex: lines.codex, session_start: lines.session_start }).join("; ")})`, "SETUP_FAILED", errors);
  }
  if (configSnapshot(options) === before) {
    return block({ guard: { ...lines, status: "already installed (no-op)" } });
  }
  return out(
    block({ guard: { ...lines, status: "installed" }, hook: hookCommand }),
    helpBlock(["The Guard is active now in Claude Code (hooks reload mid-session); restart the session for the secrets overview at session start, and for Codex"]),
  );
}
