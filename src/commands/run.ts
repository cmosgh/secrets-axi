import { spawn } from "node:child_process";
import { bool, flag, flags, parseArgs } from "../args.js";
import type { CommandContext } from "../context.js";
import { axiError, usageError } from "../errors.js";
import { MaskStream, maskTable } from "../mask.js";
import { isRevealKey, loadPolicy } from "../policy.js";
import { isJsonMode } from "../render.js";
import { fetchAwsSecrets, parseAwsSpec } from "../sources/aws.js";
import { detectSource, SUPPORTED } from "../sources/detect.js";
import { loadEnvFiles } from "../sources/dotenv.js";
import { fetchKeychain, parseKeychainSpec } from "../sources/keychain.js";
import { findEnvFiles } from "./scan.js";

export const RUN_HELP = `usage: secrets-axi run [--env-file <file>]... [--aws-secret <id>[=NAME]]... [--keychain <service>/<account>=NAME]... [--source dotenv|none] [--profile <p>] [--region <r>] [--quiet] -- <command> [args]
Guarded Run: resolve secrets, start the command with them in its environment, mask every value in its output as <NAME>. Exit code = the command's.
flags[7]:
  --env-file <file> (repeatable, in order; default: the Policy's envFiles, normally .env), --aws-secret <id> (Secrets Manager id, JSON keys become variables; <id>=NAME for a string secret; ssm:/path for Parameter Store), --keychain <service>/<account>=NAME (repeatable; a macOS keychain generic password), --source dotenv|none (skip detection), --profile/--region (aws), --quiet (no stderr summary line)
notes:
  Masking cannot be switched off. Values shorter than 4 characters and plain literals (true, false, yes, no, on, off, null, none, enabled, disabled) are not masked.
  The command runs through no shell: pass it as separate arguments after --
examples[4]:
  secrets-axi run -- pnpm test
  secrets-axi run --env-file .env.test -- pnpm vitest run
  secrets-axi run --aws-secret prod/db --aws-secret ssm:/app/token=APP_TOKEN -- node scripts/migrate.js
  secrets-axi run --keychain mysql-axi/develop=DB_PASSWORD -- npm run cli
`;

const SPECS = [
  { name: "--env-file", repeatable: true },
  { name: "--aws-secret", repeatable: true },
  { name: "--keychain", repeatable: true },
  { name: "--source" },
  { name: "--profile" },
  { name: "--region" },
  { name: "--quiet", boolean: true },
] as const;

export async function runCommand(args: string[], ctx: CommandContext): Promise<string> {
  if (isJsonMode()) throw usageError("run has no --json form: the command's own output is the result");
  const sep = args.indexOf("--");
  if (sep < 0 || sep === args.length - 1) throw usageError("missing command after --", ["Run `secrets-axi run -- <command> [args]`"]);
  const parsed = parseArgs(args.slice(0, sep), SPECS, "secrets-axi run");
  if (parsed.positionals.length > 0) throw usageError(`unexpected argument '${parsed.positionals[0]}' before --`, ["Flags go before --, the command after it"]);
  const command = args.slice(sep + 1);
  const { policy } = loadPolicy(ctx.cwd, { userPath: ctx.userPolicyPath, home: ctx.home });
  const source = flag(parsed, "--source");
  if (source !== undefined && source !== "dotenv" && source !== "none") throw usageError(`--source must be dotenv or none (got '${source}')`);

  const envFiles = flags(parsed, "--env-file");
  const detected = detectSource(ctx.cwd, policy, findEnvFiles(ctx.cwd, policy));
  if (source === undefined && envFiles.length === 0 && !SUPPORTED.has(detected.kind)) {
    throw axiError(`secret source ${detected.kind} detected (${detected.reason}) - ${detected.unsupported}`, "SOURCE_ERROR", [
      "Run with `--source dotenv` to load the env file as plain text anyway, or `--source none` to inject only --aws-secret/--keychain values",
    ]);
  }
  // Validated before anything is read.
  const keychainSpecs = flags(parsed, "--keychain").map(parseKeychainSpec);
  const env = new Map<string, string>();
  const from: string[] = [];
  if (source !== "none") {
    const files = envFiles.length > 0 ? envFiles : policy.envFiles;
    const loaded = loadEnvFiles(ctx.cwd, files);
    if (envFiles.length > 0 && loaded.missing.length > 0) throw axiError(`env file not found: ${loaded.missing.join(", ")}`, "NOT_FOUND");
    for (const [k, v] of loaded.env) env.set(k, v);
    if (loaded.loaded.length > 0) from.push(`${loaded.env.size} from ${loaded.loaded.join(", ")}`);
  }
  const awsSpecs = [...policy.aws, ...flags(parsed, "--aws-secret")].map(parseAwsSpec);
  if (awsSpecs.length > 0) {
    const aws = fetchAwsSecrets(awsSpecs, { profile: flag(parsed, "--profile"), region: flag(parsed, "--region") });
    for (const [k, v] of aws.env) env.set(k, v);
    from.push(`aws ${aws.from.join(", ")}`);
  }
  if (keychainSpecs.length > 0) {
    const keychain = fetchKeychain(keychainSpecs, ctx.keychain ? { fetch: ctx.keychain } : {});
    for (const [k, v] of keychain.env) env.set(k, v);
    from.push(`keychain ${keychain.from.join(", ")}`);
  }

  const io = ctx.io ?? { stdout: process.stdout, stderr: process.stderr };
  if (!bool(parsed, "--quiet")) {
    io.stderr.write(`secrets-axi: ${env.size} variables (${from.length > 0 ? from.join("; ") : "none"}) - output masked\n`);
  }
  // Reveal Keys (NODE_ENV, PORT, ...) are public by Policy: masking them shreds paths and ports in the output.
  const masked = new Map([...env].filter(([name]) => !isRevealKey(name, policy)));
  const code = await spawnMasked(command, env, ctx.cwd, io, masked);
  process.exitCode = code;
  return "";
}

/** Spawn with the merged environment; stdout and stderr pass through one MaskStream each over `masked` (default: everything injected). */
export function spawnMasked(
  command: string[],
  env: Map<string, string>,
  cwd: string,
  io: { stdout: NodeJS.WritableStream; stderr: NodeJS.WritableStream },
  masked: ReadonlyMap<string, string> = env,
): Promise<number> {
  const table = maskTable(masked);
  const childEnv = { ...process.env, ...Object.fromEntries(env) };
  return new Promise((resolve, reject) => {
    const child = spawn(command[0]!, command.slice(1), { cwd, env: childEnv, stdio: ["inherit", "pipe", "pipe"] });
    child.on("error", (error: NodeJS.ErrnoException) => {
      if (error.code === "ENOENT") reject(axiError(`command not found: ${command[0]}`, "RUN_FAILED", ["The command runs without a shell: give the executable, not an alias or a shell line"]));
      else reject(axiError(error.message, "RUN_FAILED"));
    });
    const out = new MaskStream(table);
    const err = new MaskStream(table);
    out.pipe(io.stdout, { end: false });
    err.pipe(io.stderr, { end: false });
    child.stdout.pipe(out);
    child.stderr.pipe(err);
    let pending = 2;
    let exit: number | null = null;
    const finish = (): void => {
      if (pending === 0 && exit !== null) resolve(exit);
    };
    out.on("finish", () => {
      pending--;
      finish();
    });
    err.on("finish", () => {
      pending--;
      finish();
    });
    child.on("close", (code, signal) => {
      exit = code ?? (signal ? 128 + 1 : 1);
      finish();
    });
  });
}
