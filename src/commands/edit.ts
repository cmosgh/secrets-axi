import { closeSync, existsSync, openSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { expectPositionals, parseArgs } from "../args.js";
import type { CommandContext } from "../context.js";
import { axiError, usageError } from "../errors.js";
import { setKey, unsetKey } from "../env.js";
import { display } from "../hook/guard.js";
import { expandHome } from "../policy.js";
import { block, helpBlock, out } from "../render.js";

export const SET_HELP = `usage: secrets-axi set <file> KEY=value
Add or replace one variable in a dotenv file in place; every other line stays. Nothing but the key name is printed. A missing file is created (mode 600).
examples[2]:
  secrets-axi set .env FEATURE_X=true
  secrets-axi set .env.local DATABASE_URL='postgres://u:p@localhost/db'
`;

export const UNSET_HELP = `usage: secrets-axi unset <file> KEY
Remove every assignment of KEY from a dotenv file in place.
examples[1]:
  secrets-axi unset .env OLD_TOKEN
`;

const KEY = /^[A-Za-z_][A-Za-z0-9_.-]*$/;

export async function setCommand(args: string[], ctx: CommandContext): Promise<string> {
  const parsed = parseArgs(args, [], "secrets-axi set");
  expectPositionals(parsed, 2, "secrets-axi set <file> KEY=value");
  const [rawFile, assignment] = parsed.positionals as [string, string];
  const eq = assignment.indexOf("=");
  if (eq <= 0) throw usageError("expected KEY=value", ["Quote the whole pair when the value has spaces: `secrets-axi set .env 'MSG=hello world'`"]);
  const key = assignment.slice(0, eq);
  const value = assignment.slice(eq + 1);
  if (!KEY.test(key)) throw usageError(`'${key}' is not a variable name`);
  const abs = resolve(ctx.cwd, expandHome(rawFile, ctx.home));
  if (!existsSync(abs)) {
    if (!existsSync(dirname(abs))) throw axiError(`directory does not exist: ${dirname(rawFile)}`, "NOT_FOUND");
    closeSync(openSync(abs, "w", 0o600));
  }
  const result = setKey(abs, key, value);
  const file = display(abs, ctx.cwd, ctx.home);
  return out(block({ file, key: result.key, action: result.action, line: result.line }), helpBlock([`Run \`secrets-axi keys ${file}\` to see the variables`]));
}

export async function unsetCommand(args: string[], ctx: CommandContext): Promise<string> {
  const parsed = parseArgs(args, [], "secrets-axi unset");
  expectPositionals(parsed, 2, "secrets-axi unset <file> KEY");
  const [rawFile, key] = parsed.positionals as [string, string];
  if (!KEY.test(key)) throw usageError(`'${key}' is not a variable name`);
  const abs = resolve(ctx.cwd, expandHome(rawFile, ctx.home));
  if (!existsSync(abs)) throw axiError(`no such file: ${rawFile}`, "NOT_FOUND");
  const result = unsetKey(abs, key);
  const file = display(abs, ctx.cwd, ctx.home);
  return block({ file, key: result.key, action: result.action, ...(result.line > 0 ? { line: result.line } : {}) });
}
