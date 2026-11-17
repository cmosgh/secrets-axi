import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import { basename, resolve } from "node:path";
import { expectPositionals, flag, parseArgs, parseFields } from "../args.js";
import type { CommandContext } from "../context.js";
import { axiError, usageError } from "../errors.js";
import { parseEnv, shapeOf } from "../env.js";
import { display } from "../hook/guard.js";
import { expandHome, isRevealKey, loadPolicy } from "../policy.js";
import { block, helpBlock, out } from "../render.js";

export const KEYS_HELP = `usage: secrets-axi keys <file>|<host>:<path> [--sudo-user <user>] [--fields name,shape,line|all]
Key listing of a Secret File: variable names, whether each is set, and the shape of its value (length and character class). Values are shown only for Reveal Keys (NODE_ENV, PORT, PUBLIC_* ...; see \`secrets-axi policy\`).
formats: dotenv (.env*, .envrc exports), ini (~/.aws/credentials: profile.key), json (top-level keys); other files give size and line count only
remote: <host>:<path> reads the file over ssh (BatchMode, \`cat\`, \`sudo -n -u <user>\` with --sudo-user) and applies the local Policy; no secrets-axi or Node needed on the host
examples[3]:
  secrets-axi keys .env
  secrets-axi keys ~/.aws/credentials
  secrets-axi keys stg1:/apps/api/.env --sudo-user app
`;

const FIELDS = ["name", "shape", "line"] as const;

interface KeyRow {
  name: string;
  shape: string;
  line: number;
  value: string;
}

export async function keysCommand(args: string[], ctx: CommandContext): Promise<string> {
  const parsed = parseArgs(args, [{ name: "--fields" }, { name: "--sudo-user" }], "secrets-axi keys");
  expectPositionals(parsed, 1, "secrets-axi keys <file>|<host>:<path>");
  const chosen = parseFields(flag(parsed, "--fields"), FIELDS);
  const fields = (chosen.length > 0 ? ["name", ...chosen.filter((f) => f !== "name")] : ["name", "shape"]) as Array<(typeof FIELDS)[number]>;
  const raw = parsed.positionals[0]!;
  const sudoUser = flag(parsed, "--sudo-user");
  const abs = resolve(ctx.cwd, expandHome(raw, ctx.home));
  const remote = existsSync(abs) ? undefined : remoteTarget(raw);
  if (sudoUser !== undefined && !remote) throw usageError("--sudo-user applies to <host>:<path> only");
  let text: string;
  let file: string;
  if (remote) {
    text = readRemote(remote.host, remote.path, sudoUser);
    file = raw;
  } else {
    if (!existsSync(abs)) throw axiError(`no such file: ${raw}`, "NOT_FOUND", ["Run `secrets-axi` for the Secret Files in this repository"]);
    if (!statSync(abs).isFile()) throw usageError(`${raw} is not a file`);
    text = readFileSync(abs, "utf8");
    file = display(abs, ctx.cwd, ctx.home);
  }
  const { policy } = loadPolicy(ctx.cwd, { userPath: ctx.userPolicyPath, home: ctx.home });
  const { format, rows } = parseAny(text, basename(remote ? remote.path : abs));
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
    helpBlock(
      remote
        ? []
        : [
            `Run \`secrets-axi run -- <command>\` to run with ${file} loaded (values masked in the output)`,
            ...(format === "dotenv" ? [`Run \`secrets-axi set ${file} KEY=value\` to add or change a variable`] : []),
          ],
    ),
  );
}

/** `host:/abs/path` or `host:~/path` (host may be `user@host` or an ssh alias); a local file of that name wins. */
export function remoteTarget(raw: string): { host: string; path: string } | undefined {
  const m = raw.match(/^([A-Za-z0-9_.@-]+):((?:\/|~\/)\S.*)$/);
  return m ? { host: m[1]!, path: m[2]! } : undefined;
}

function shellWord(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/** Remote shell line that prints the file; `~/` stays unquoted so the remote shell expands it. */
export function remoteCatLine(path: string, sudoUser?: string): string {
  const target = path.startsWith("~/") ? `~/${shellWord(path.slice(2))}` : shellWord(path);
  return `${sudoUser ? `sudo -n -u ${shellWord(sudoUser)} ` : ""}cat -- ${target}`;
}

/** The file's text over ssh. Errors name host and path only; the remote stderr is not echoed (it could quote file content). */
function readRemote(host: string, path: string, sudoUser?: string): string {
  // spawnSync, not execFileSync: the latter copies the child's stderr (ssh banners and warnings) to ours.
  const r = spawnSync("ssh", ["-o", "BatchMode=yes", "-o", "LogLevel=ERROR", "--", host, remoteCatLine(path, sudoUser)], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    maxBuffer: 4 * 1024 * 1024,
    timeout: 30_000,
  });
  if (r.status === 0) return r.stdout;
  if ((r.error as NodeJS.ErrnoException | undefined)?.code === "ENOENT") throw axiError("ssh not found", "RUN_FAILED");
  const stderr = r.stderr ?? "";
  if (r.status === 255) throw axiError(`ssh to ${host} failed`, "RUN_FAILED", [`Check \`ssh ${host} true\` works without a prompt (keys run with BatchMode)`]);
  if (/password is required|not allowed|sudoers/i.test(stderr)) throw axiError(`sudo -n -u ${sudoUser} refused on ${host}`, "RUN_FAILED", ["The ssh user needs passwordless sudo to that user"]);
  if (/permission denied/i.test(stderr)) throw axiError(`permission denied: ${host}:${path}`, "RUN_FAILED", [`Run \`secrets-axi keys ${host}:${path} --sudo-user <owner>\` to read it as the file's owner`]);
  if (/no such file|not a directory/i.test(stderr)) throw axiError(`no such file: ${host}:${path}`, "NOT_FOUND");
  throw axiError(`reading ${host}:${path} failed (exit ${r.status ?? "?"})`, "RUN_FAILED");
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
