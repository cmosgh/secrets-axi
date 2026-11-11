import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "../args.js";
import type { CommandContext } from "../context.js";
import { parseEnv } from "../env.js";
import { loadPolicy } from "../policy.js";
import { block, helpBlock, out } from "../render.js";
import { guardStatus } from "../setup/index.js";
import { detectSource } from "../sources/detect.js";
import { findEnvFiles, scanSecretFiles } from "./scan.js";

/** Session-start view: names and counts only, bounded scan, exit 0 anywhere. */
export async function homeCommand(args: string[], ctx: CommandContext): Promise<string> {
  parseArgs(args, [], "secrets-axi");
  const load = loadPolicy(ctx.cwd, { userPath: ctx.userPolicyPath, home: ctx.home });
  const { policy } = load;
  const scan = scanSecretFiles(ctx.cwd, policy);
  const envFiles = findEnvFiles(ctx.cwd, policy);
  const detected = detectSource(ctx.cwd, policy, envFiles);
  const tracked = trackedByGit(ctx.cwd, scan.files);
  const files = scan.files.map((f) => {
    const count = /\.env|\.envrc|\.secrets/.test(f) ? keyCount(join(ctx.cwd, f)) : undefined;
    return `${f}${count !== undefined ? ` (${count} keys)` : ""}${tracked.has(f) ? " TRACKED BY GIT" : ""}`;
  });
  let guard: string;
  try {
    const status = guardStatus({ scope: "user", cwd: ctx.cwd, homeDir: ctx.home });
    const on = [status.claude.installed ? "Claude Code" : "", status.codex.installed ? "Codex" : ""].filter(Boolean);
    guard = on.length > 0 ? `active (${on.join(", ")})` : "not installed";
  } catch {
    guard = "unknown";
  }
  const source = detected.kind === "none" ? detected.reason : `${detected.kind} (${detected.reason})${detected.unsupported ? " - not supported yet" : ""}`;
  const help = [
    "Run `secrets-axi run -- <command>` instead of sourcing .env: secrets are injected and masked in the output",
    ...(scan.files[0] ? [`Run \`secrets-axi keys ${scan.files.find((f) => f.startsWith(".env")) ?? scan.files[0]}\` for variable names and shapes (never values)`] : []),
    ...(guard === "not installed" ? ["Run `secrets-axi setup hooks` to install the Guard for Claude Code and Codex"] : []),
    ...(tracked.size > 0 ? [`${[...tracked].join(", ")} is tracked by git: \`git diff\`/\`git log -p\` can print it and the Guard cannot cover that; untrack it`] : []),
    ...(load.broken.map((b) => `${b} is not valid JSON and was skipped`)),
  ];
  return out(
    block({
      guard,
      secret_files: files.length > 0 ? files : "none found",
      ...(scan.capped ? { scan: "partial (large tree)" } : {}),
      source,
      ...(detected.otherEnvFiles.length > 0 ? { not_loaded: detected.otherEnvFiles.join(", ") } : {}),
      ...(policy.aws.length > 0 ? { aws: policy.aws.join(", ") } : {}),
    }),
    helpBlock(help),
  );
}

function keyCount(path: string): number | undefined {
  try {
    return parseEnv(readFileSync(path, "utf8")).length;
  } catch {
    return undefined;
  }
}

function trackedByGit(cwd: string, files: string[]): Set<string> {
  if (files.length === 0) return new Set();
  const result = spawnSync("git", ["ls-files", "--error-unmatch", "--", ...files], { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
  if (result.error || result.status === null) return new Set();
  return new Set(result.stdout.split("\n").filter(Boolean));
}
