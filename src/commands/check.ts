import { flag, parseArgs } from "../args.js";
import type { CommandContext } from "../context.js";
import { usageError } from "../errors.js";
import { decide, type ToolCall } from "../hook/guard.js";
import { loadPolicy } from "../policy.js";
import { block, helpBlock, out } from "../render.js";

export const CHECK_HELP = `usage: secrets-axi check '<shell command>' | --read <path> | --edit <path> | --grep <path|dir>
Dry run of the Guard: the decision it would make for that tool call, the Policy rule behind it and the Hint the agent would get. Nothing is executed or read.
examples[3]:
  secrets-axi check 'cat .env | grep DB'
  secrets-axi check 'docker run --env-file .env app'
  secrets-axi check --read ~/.aws/credentials
`;

export async function checkCommand(args: string[], ctx: CommandContext): Promise<string> {
  const parsed = parseArgs(args, [{ name: "--read" }, { name: "--edit" }, { name: "--grep" }], "secrets-axi check");
  const read = flag(parsed, "--read");
  const edit = flag(parsed, "--edit");
  const grep = flag(parsed, "--grep");
  const command = parsed.positionals.join(" ");
  const given = [read, edit, grep, command || undefined].filter((v) => v !== undefined).length;
  if (given !== 1) throw usageError("give exactly one of: a shell command, --read <path>, --edit <path>, --grep <path>");
  const call: ToolCall = read
    ? { tool: "Read", input: { file_path: read }, cwd: ctx.cwd }
    : edit
      ? { tool: "Edit", input: { file_path: edit, old_string: "", new_string: "" }, cwd: ctx.cwd }
      : grep
        ? { tool: "Grep", input: { pattern: "x", path: grep }, cwd: ctx.cwd }
        : { tool: "Bash", input: { command }, cwd: ctx.cwd };
  const { policy, broken } = loadPolicy(ctx.cwd, { userPath: ctx.userPolicyPath, home: ctx.home });
  const decision = decide(call, policy, { home: ctx.home });
  const base = { tool: call.tool, call: read ?? edit ?? grep ?? command };
  if (decision.kind === "pass") {
    return out(block({ ...base, decision: "pass" }), helpBlock(broken.map((b) => `Policy file ${b} is not valid JSON and was skipped`)));
  }
  if (decision.kind === "deny") {
    return block({ ...base, decision: "deny", rule: decision.rule, ...(decision.file ? { file: decision.file } : {}), hint: decision.hint });
  }
  const rewritten = call.tool === "Bash" ? decision.input["command"] : decision.input["glob"];
  return block({ ...base, decision: "rewrite", rule: decision.rule, rewritten, note: decision.note });
}
