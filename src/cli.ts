import { runAxiCli } from "axi-sdk-js";
import { checkCommand, CHECK_HELP } from "./commands/check.js";
import { SET_HELP, setCommand, UNSET_HELP, unsetCommand } from "./commands/edit.js";
import { homeCommand } from "./commands/home.js";
import { keysCommand, KEYS_HELP } from "./commands/keys.js";
import { policyCommand, POLICY_HELP } from "./commands/policy.js";
import { runCommand, RUN_HELP } from "./commands/run.js";
import { setupCommand, SETUP_HELP } from "./commands/setup.js";
import type { CommandContext } from "./context.js";
import { AxiError, exitCodeForError } from "./errors.js";
import { DESCRIPTION, TOP_HELP } from "./meta.js";
import { renderErrorOutput, setJsonMode, toJson } from "./render.js";
import { VERSION } from "./version.js";

export { DESCRIPTION, TOP_HELP };

const COMMAND_HELP: Record<string, string> = {
  run: RUN_HELP,
  keys: KEYS_HELP,
  set: SET_HELP,
  unset: UNSET_HELP,
  check: CHECK_HELP,
  policy: POLICY_HELP,
  setup: SETUP_HELP,
};

type Handler = (args: string[], ctx: CommandContext) => Promise<string>;

function command(name: string, handler: Handler, ctx: CommandContext): (args: string[]) => Promise<string> {
  return async (args) => {
    const own = args.includes("--") ? args.slice(0, args.indexOf("--")) : args;
    if (own.includes("-h") || own.includes("--help")) return (COMMAND_HELP[name] ?? "").trimEnd();
    return handler(args, ctx);
  };
}

function formatError(error: unknown): { output: string; exitCode: number } {
  const axi = error instanceof AxiError ? error : new AxiError(error instanceof Error ? error.message : String(error), "UNKNOWN");
  return { output: `${renderErrorOutput(axi.message, axi.code, axi.suggestions)}\n`, exitCode: exitCodeForError(axi) };
}

export interface MainOptions {
  argv?: string[];
  stdout?: { write: (chunk: string) => unknown };
  cwd?: string;
  home?: string;
  userPolicyPath?: string;
  io?: CommandContext["io"];
}

export async function main(options: MainOptions = {}): Promise<void> {
  const argv = options.argv ?? process.argv.slice(2);
  // Flags after `--` belong to the child command of `run`, never to secrets-axi.
  const own = argv.includes("--") ? argv.slice(0, argv.indexOf("--")) : argv;
  const json = own.includes("--json");
  setJsonMode(json);
  const stdout = options.stdout ?? process.stdout;
  const ctx: CommandContext = {
    cwd: options.cwd ?? process.cwd(),
    ...(options.home !== undefined ? { home: options.home } : {}),
    ...(options.userPolicyPath !== undefined ? { userPolicyPath: options.userPolicyPath } : {}),
    ...(options.io !== undefined ? { io: options.io } : {}),
  };
  // `run` bypasses the SDK dispatcher: its child's flags (`--help`, `--json`) are not ours, and its output is the child's.
  if (argv[0] === "run" && !json) {
    try {
      const output = own.includes("-h") || own.includes("--help") ? RUN_HELP.trimEnd() : await runCommand(argv.slice(1), ctx);
      if (output) stdout.write(`${output}\n`);
    } catch (error) {
      const { output, exitCode } = formatError(error);
      stdout.write(output);
      process.exitCode = exitCode;
    }
    return;
  }
  let buffered = "";
  try {
    await runAxiCli({
      argv: json ? own.filter((a) => a !== "--json") : argv,
      stdout: json ? { write: (chunk: string) => (buffered += chunk) } : stdout,
      description: DESCRIPTION,
      version: VERSION,
      topLevelHelp: TOP_HELP,
      home: (args) => homeCommand(args, ctx),
      commands: {
        run: command("run", runCommand, ctx),
        keys: command("keys", keysCommand, ctx),
        set: command("set", setCommand, ctx),
        unset: command("unset", unsetCommand, ctx),
        check: command("check", checkCommand, ctx),
        policy: command("policy", policyCommand, ctx),
        setup: command("setup", setupCommand, ctx),
        hook: async () => "The hook entry is `secrets-axi hook` with a PreToolUse JSON object on stdin; agents call it, not people. Run `secrets-axi check '<command>'` for a dry run",
      },
      getCommandHelp: (name) => COMMAND_HELP[name],
      renderUnknownCommand: (name) =>
        `${renderErrorOutput(`unknown command '${name}'`, "VALIDATION_ERROR", [
          "commands: run, keys, set, unset, check, policy, setup (no command = secrets overview)",
          "Run `secrets-axi --help` for examples",
        ])}\n`,
      formatError,
    });
  } finally {
    setJsonMode(false);
  }
  if (!json) return;
  if (stdout === process.stdout) {
    process.stdout.on("error", (error: NodeJS.ErrnoException) => {
      if (error.code !== "EPIPE") throw error;
    });
  }
  stdout.write(toJson(buffered));
}
