import { existsSync, readFileSync, statSync } from "node:fs";
import { basename, resolve } from "node:path";
import { expectPositionals, flag, parseArgs, parseFields } from "../args.js";
import type { CommandContext } from "../context.js";
import { axiError, usageError } from "../errors.js";
import { parseEnv, shapeOf } from "../env.js";
import { display } from "../hook/guard.js";
import { expandHome, isRevealKey, loadPolicy } from "../policy.js";
import { block, helpBlock, out } from "../render.js";

export const KEYS_HELP = `usage: secrets-axi keys <file> [--fields name,shape,line|all]
Key listing of a Secret File: variable names, whether each is set, and the shape of its value (length and character class). Values are shown only for Reveal Keys (NODE_ENV, PORT, PUBLIC_* ...; see \`secrets-axi policy\`).
formats: dotenv (.env*, .envrc exports), ini (~/.aws/credentials: profile.key), json (top-level keys); other files give size and line count only
examples[2]:
  secrets-axi keys .env
  secrets-axi keys ~/.aws/credentials
`;

const FIELDS = ["name", "shape", "line"] as const;

interface KeyRow {
  name: string;
  shape: string;
  line: number;
  value: string;
}

export async function keysCommand(args: string[], ctx: CommandContext): Promise<string> {
  const parsed = parseArgs(args, [{ name: "--fields" }], "secrets-axi keys");
  expectPositionals(parsed, 1, "secrets-axi keys <file>");
  const chosen = parseFields(flag(parsed, "--fields"), FIELDS);
  const fields = (chosen.length > 0 ? ["name", ...chosen.filter((f) => f !== "name")] : ["name", "shape"]) as Array<(typeof FIELDS)[number]>;
  const raw = parsed.positionals[0]!;
  const abs = resolve(ctx.cwd, expandHome(raw, ctx.home));
  if (!existsSync(abs)) throw axiError(`no such file: ${raw}`, "NOT_FOUND", ["Run `secrets-axi` for the Secret Files in this repository"]);
  if (!statSync(abs).isFile()) throw usageError(`${raw} is not a file`);
  const { policy } = loadPolicy(ctx.cwd, { userPath: ctx.userPolicyPath, home: ctx.home });
  const text = readFileSync(abs, "utf8");
  const file = display(abs, ctx.cwd, ctx.home);
  const { format, rows } = parseAny(text, basename(abs));
  const revealed: Record<string, string> = {};
  for (const r of rows) if (isRevealKey(r.name, policy)) revealed[r.name] = r.value;
  const table = rows.map((r) => Object.fromEntries(fields.map((f) => [f, r[f]])));
  const lines = text.split("\n").length;
  return out(
    block({
      file,
      format,
      ...(format === "text" ? { size: `${text.length} chars, ${lines} lines` } : { keys: table }),
      ...(Object.keys(revealed).length > 0 ? { revealed } : {}),
    }),
    helpBlock([
      `Run \`secrets-axi run -- <command>\` to run with ${file} loaded (values masked in the output)`,
      ...(format === "dotenv" ? [`Run \`secrets-axi set ${file} KEY=value\` to add or change a variable`] : []),
    ]),
  );
}

function parseAny(text: string, name: string): { format: "dotenv" | "ini" | "json" | "text"; rows: KeyRow[] } {
  if (name.endsWith(".json") || /^\s*\{/.test(text)) {
    try {
      const obj = JSON.parse(text) as Record<string, unknown>;
      if (obj && typeof obj === "object" && !Array.isArray(obj)) {
        return {
          format: "json",
          rows: Object.entries(obj).map(([k, v], i) => ({ name: k, shape: typeof v === "string" ? shapeOf(v) : typeof v === "object" && v !== null ? `${Array.isArray(v) ? "array" : "object"} (${Object.keys(v).length})` : typeof v, line: i + 1, value: typeof v === "string" ? v : JSON.stringify(v) })),
        };
      }
    } catch {
      // fall through
    }
  }
  if (/^\s*\[[^\]]+\]\s*$/m.test(text)) {
    const rows: KeyRow[] = [];
    let section = "";
    text.split(/\r?\n/).forEach((line, i) => {
      const sec = line.match(/^\s*\[([^\]]+)\]\s*$/);
      if (sec) {
        section = sec[1]!.replace(/^profile\s+/, "");
        return;
      }
      const kv = line.match(/^\s*([A-Za-z_][\w.-]*)\s*=\s*(.*)$/);
      if (kv) rows.push({ name: section ? `${section}.${kv[1]}` : kv[1]!, shape: shapeOf(kv[2]!.trim()), line: i + 1, value: kv[2]!.trim() });
    });
    return { format: "ini", rows };
  }
  const entries = parseEnv(text);
  if (entries.length > 0 || /^\.env/.test(name)) {
    return { format: "dotenv", rows: entries.map((e) => ({ name: e.key, shape: shapeOf(e.value), line: e.line, value: e.value })) };
  }
  return { format: "text", rows: [] };
}
