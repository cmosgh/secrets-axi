// PreToolUse hook entry for Claude Code and Codex (same contract). Reads one JSON object on stdin,
// prints a decision on stdout. Loads nothing beyond node builtins, the policy and the guard.
import { homedir } from "node:os";
import { loadPolicy } from "../policy.js";
import { decide, type Decision, type ToolCall } from "./guard.js";

interface HookInput {
  hook_event_name?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  cwd?: string;
}

export function hookOutput(decision: Decision): string | undefined {
  if (decision.kind === "pass") return undefined;
  if (decision.kind === "deny") {
    return JSON.stringify({
      hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: `secrets-axi: ${decision.hint}` },
    });
  }
  return JSON.stringify({
    hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow", updatedInput: decision.input, permissionDecisionReason: `secrets-axi: ${decision.note}` },
  });
}

export function callFromHookInput(raw: string): ToolCall | undefined {
  let parsed: HookInput;
  try {
    parsed = JSON.parse(raw) as HookInput;
  } catch {
    return undefined;
  }
  if (!parsed || typeof parsed.tool_name !== "string" || !parsed.tool_input || typeof parsed.tool_input !== "object") return undefined;
  return { tool: parsed.tool_name, input: parsed.tool_input, cwd: typeof parsed.cwd === "string" && parsed.cwd !== "" ? parsed.cwd : process.cwd() };
}

/** `secrets-axi hook`: the installed command. A broken stdin or policy means pass (never block the agent on our own bug). */
export async function runHook(stdin: NodeJS.ReadableStream = process.stdin, stdout: { write: (s: string) => unknown } = process.stdout): Promise<number> {
  const chunks: Buffer[] = [];
  for await (const chunk of stdin) chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  const call = callFromHookInput(Buffer.concat(chunks).toString("utf8"));
  if (!call) return 0;
  try {
    const { policy } = loadPolicy(call.cwd);
    const output = hookOutput(decide(call, policy, { home: homedir() }));
    if (output) stdout.write(`${output}\n`);
  } catch {
    return 0;
  }
  return 0;
}
