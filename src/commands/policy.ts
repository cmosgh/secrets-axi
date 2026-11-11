import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { bool, expectPositionals, parseArgs } from "../args.js";
import type { CommandContext } from "../context.js";
import { usageError } from "../errors.js";
import { LIST_KEYS, loadPolicy, type ListKey, type PolicyLayer } from "../policy.js";
import { block, helpBlock, out } from "../render.js";

export const POLICY_HELP = `usage: secrets-axi policy [<list>] | policy add <list> <value> [--remove] | policy drop <list> <value>
The effective Policy: built-in, then ~/.config/secrets-axi/policy.json, then .secrets-axi.json in the repository (adds only). Each entry shows the layer it comes from.
lists[7]: secretFiles, secretFileExceptions, fetchCommands, consumers, reveal, envFiles, aws
  add <list> <value>: append to the user layer; add --remove <list> <value>: hide a built-in entry (user layer only); drop: undo an add/remove
examples[3]:
  secrets-axi policy secretFiles
  secrets-axi policy add reveal API_BASE_URL
  secrets-axi policy add secretFiles 'config/*.secret.yaml'
`;

function isList(name: string): name is ListKey {
  return (LIST_KEYS as readonly string[]).includes(name);
}

export async function policyCommand(args: string[], ctx: CommandContext): Promise<string> {
  const [first, ...rest] = args;
  if (first === "add" || first === "drop") return editUser(first, rest, ctx);
  const parsed = parseArgs(args, [], "secrets-axi policy");
  const only = parsed.positionals[0];
  if (parsed.positionals.length > 1 || (only !== undefined && !isList(only))) {
    throw usageError(only && !isList(only) ? `unknown list '${only}'` : "too many arguments", [`lists: ${LIST_KEYS.join(", ")}`]);
  }
  const load = loadPolicy(ctx.cwd, { userPath: ctx.userPolicyPath, home: ctx.home });
  const lists: Record<string, unknown> = {};
  for (const key of only ? [only] : LIST_KEYS) {
    lists[key] = load.policy[key].map((v) => {
      const origin = load.origin[key].get(v);
      return origin === "builtin" ? v : `${v} (${origin})`;
    });
  }
  return out(
    block({
      layers: { builtin: "yes", user: existsSync(load.userPath) ? load.userPath : `${load.userPath} (absent)`, repo: load.repoPath ?? "none" },
      ...lists,
    }),
    helpBlock([
      ...load.broken.map((b) => `${b} is not valid JSON and was skipped`),
      "Run `secrets-axi check '<command>'` to see which entry decides a call",
    ]),
  );
}

async function editUser(action: "add" | "drop", args: string[], ctx: CommandContext): Promise<string> {
  const parsed = parseArgs(args, [{ name: "--remove", boolean: true }], `secrets-axi policy ${action}`);
  expectPositionals(parsed, 2, `secrets-axi policy ${action} <list> <value>`);
  const [list, value] = parsed.positionals as [string, string];
  if (!isList(list)) throw usageError(`unknown list '${list}'`, [`lists: ${LIST_KEYS.join(", ")}`]);
  const remove = bool(parsed, "--remove");
  const path = ctx.userPolicyPath ?? loadPolicy(ctx.cwd, { home: ctx.home }).userPath;
  let layer: PolicyLayer = {};
  if (existsSync(path)) {
    try {
      layer = JSON.parse(readFileSync(path, "utf8")) as PolicyLayer;
    } catch {
      throw usageError(`${path} is not valid JSON; fix or delete it first`);
    }
  }
  const target: Partial<Record<ListKey, string[]>> = remove ? (layer.remove ??= {}) : layer;
  const current = target[list] ?? [];
  const next = action === "add" ? (current.includes(value) ? current : [...current, value]) : current.filter((v) => v !== value);
  target[list] = next;
  if (next.length === 0) delete target[list];
  if (layer.remove && Object.keys(layer.remove).length === 0) delete layer.remove;
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(layer, null, 2)}\n`);
  return out(
    block({ policy: path, list, value, action: action === "add" ? (remove ? "removed from the effective policy" : "added") : "dropped" }),
    helpBlock([`Run \`secrets-axi policy ${list}\` to see the effective list`]),
  );
}
