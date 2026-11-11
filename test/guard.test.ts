import { describe, expect, it } from "vitest";
import { decide, type Decision, type ToolCall } from "../src/hook/guard.js";
import { hookOutput } from "../src/hook/entry.js";
import { parseCommand, programOf } from "../src/hook/tokenize.js";
import { BUILTIN } from "../src/policy.js";

const HOME = "/home/u";
const CWD = "/home/u/repo";
const call = (tool: string, input: Record<string, unknown>, cwd = CWD): ToolCall => ({ tool, input, cwd });
const guard = (tool: string, input: Record<string, unknown>): Decision => decide(call(tool, input), BUILTIN, { home: HOME });
const bash = (command: string): Decision => guard("Bash", { command });
const kind = (d: Decision): string => d.kind;

describe("tokenizer", () => {
  it("splits on operators, keeps quotes together, finds substitutions and redirection targets", () => {
    const cmds = parseCommand(`export $(cat .env | xargs) && FOO='a b' node -e "x" < .env.local; echo \`cat x\``);
    const texts = cmds.map((c) => c.tokens.map((t) => (t.redirect ? `<${t.text}` : t.text)).join(" "));
    expect(texts).toEqual(["cat .env", "xargs", "export $(cat .env | xargs)", "FOO=a b node -e x <.env.local", "cat x", "echo `cat x`"]);
    expect(programOf(cmds[3]!)).toEqual({ name: "node", index: 1 });
  });
  it("skips wrappers and their options to find the program", () => {
    const [cmd] = parseCommand("sudo -u app env FOO=1 timeout 5 /usr/bin/cat .env");
    expect(programOf(cmd!)).toMatchObject({ name: "cat" });
  });
});

describe("file tools", () => {
  it("denies Read of a Secret File with a keys hint and passes other files", () => {
    const d = guard("Read", { file_path: `${CWD}/.env` });
    expect(d).toMatchObject({ kind: "deny", rule: "secretFiles:.env", file: ".env" });
    expect((d as { hint: string }).hint).toContain("`secrets-axi keys .env`");
    expect(kind(guard("Read", { file_path: `${CWD}/.env.example` }))).toBe("pass");
    expect(kind(guard("Read", { file_path: `${CWD}/src/env.ts` }))).toBe("pass");
    expect(kind(guard("Read", { file_path: `${CWD}/config/.env.production` }))).toBe("deny");
  });
  it("covers home credentials and private keys, not public keys or ~/.aws/config", () => {
    expect(guard("Read", { file_path: `${HOME}/.aws/credentials` })).toMatchObject({ kind: "deny", file: "~/.aws/credentials" });
    expect(kind(guard("Read", { file_path: `${HOME}/.ssh/id_ed25519` }))).toBe("deny");
    expect(kind(guard("Read", { file_path: `${HOME}/.ssh/id_ed25519.pub` }))).toBe("pass");
    expect(kind(guard("Read", { file_path: `${HOME}/.aws/config` }))).toBe("pass");
    expect(kind(guard("Read", { file_path: `${CWD}/certs/server.pem` }))).toBe("deny");
  });
  it("denies Edit and Write with a set/unset hint", () => {
    const d = guard("Edit", { file_path: `${CWD}/.env`, old_string: "A=1", new_string: "A=2" });
    expect(d.kind).toBe("deny");
    expect((d as { hint: string }).hint).toContain("`secrets-axi set .env KEY=value`");
    expect(kind(guard("Write", { file_path: `${CWD}/.env.local`, content: "X=1" }))).toBe("deny");
  });
});

describe("Grep tool", () => {
  it("denies a Secret File path, rewrites a directory search with an exclusion glob, leaves a narrowed search alone", () => {
    expect(kind(guard("Grep", { pattern: "PASS", path: `${CWD}/.env` }))).toBe("deny");
    const d = guard("Grep", { pattern: "TODO", path: CWD });
    expect(d.kind).toBe("rewrite");
    expect((d as { input: Record<string, unknown> }).input["glob"]).toMatch(/^!\{\.env,\.env\.\*,/);
    expect(kind(guard("Grep", { pattern: "TODO", glob: "*.ts" }))).toBe("pass");
    expect(kind(guard("Grep", { pattern: "DB_", glob: ".env" }))).toBe("deny");
  });
});

describe("Bash reads", () => {
  it.each([
    "cat .env",
    "head -n 5 ./.env.local",
    "source .env && pnpm dev",
    ". ./.env",
    "export $(cat .env | xargs)",
    "set -a; source .env; set +a; node app.js",
    "grep DB_PASSWORD .env",
    "sed -n 1,5p config/.env.production",
    "node -e 'console.log(1)' < .env",
    "cat ~/.aws/credentials",
    "less $HOME/.ssh/id_rsa",
    "base64 -w0 certs/key.pem",
    "git show HEAD:.env",
    "python3 -c 'print(open(\".env\").read())'",
    "cp .env /tmp/x && cat /tmp/x",
  ])("denies %s", (command) => {
    expect(bash(command).kind).toBe("deny");
  });

  it("the hint keeps the non-reading part of the command", () => {
    const d = bash("source .env && pnpm dev") as { hint: string };
    expect(d.hint).toContain("`secrets-axi run -- pnpm dev`");
    const d2 = bash("set -a; source .env; set +a; node app.js") as { hint: string };
    expect(d2.hint).toContain("`secrets-axi run -- set -a && set +a && node app.js`");
  });

  it.each([
    "docker run --env-file .env app",
    "docker compose --env-file .env.staging up",
    "dotenv -e .env.test -- vitest",
    "dotenvx run -f .env -- node app.js",
    "op run --env-file=.env -- pnpm start",
    "ls -la .env",
    "rm .env.bak",
    "test -f .env && echo present",
    "git add .env.example",
    "cat .env.example",
    "cat README.md",
    "echo '.env' >> .gitignore",
    "pnpm test",
  ])("passes %s", (command) => {
    expect(bash(command).kind).toBe("pass");
  });

  it("the Runner is not a way around the Guard; keys/set/check may name the file", () => {
    expect(bash("secrets-axi run --source none -- cat .env").kind).toBe("deny");
    expect(bash("secrets-axi run --env-file .env.test -- cat ~/.aws/credentials").kind).toBe("deny");
    expect(bash("secrets-axi run -- aws secretsmanager get-secret-value --secret-id x").kind).toBe("deny");
    expect(bash("secrets-axi run -- pnpm test").kind).toBe("pass");
    expect(bash("secrets-axi keys .env && secrets-axi set .env A=1 && secrets-axi check 'cat .env'").kind).toBe("pass");
  });

  it("glob tokens that could name a Secret File are reads; dot-only names are not key files", () => {
    expect(bash("cat .env*").kind).toBe("deny");
    expect(bash("head certs/*.pem").kind).toBe("deny");
    expect(bash("grep -r X --include=.env* .").kind).toBe("deny");
    expect(bash("rg -g '.env*' TOKEN").kind).toBe("deny");
    expect(bash("jq .key data.json").kind).toBe("pass");
    expect(bash("cat src/*.ts").kind).toBe("pass");
  });

  it("a consumer that takes the file only as its flag value does not excuse other reads", () => {
    expect(bash("docker run --env-file .env app && cat .env").kind).toBe("deny");
    expect(bash("docker cp .env app:/x").kind).toBe("deny");
  });
});

describe("Bash Secret Fetch", () => {
  it.each([
    ["aws secretsmanager get-secret-value --secret-id prod/db", "prod/db"],
    ["aws --profile x ssm get-parameter --name /app/token --with-decryption", "/app/token"],
    ["op read op://dev/db/password", undefined],
    ["vault kv get secret/app", undefined],
    ["doppler secrets download --no-file --format env", undefined],
    ["gh auth token", undefined],
  ])("denies %s", (command, id) => {
    const d = bash(command);
    expect(d.kind).toBe("deny");
    expect((d as { rule: string }).rule).toMatch(/^fetchCommands:/);
    if (id) expect((d as { hint: string }).hint).toContain(`--aws-secret ${id}`);
  });
  it.each(["aws secretsmanager list-secrets", "aws secretsmanager describe-secret --secret-id prod/db", "aws ssm get-parameter --name /app/region", "aws sts get-caller-identity", "doppler setup"])(
    "passes %s",
    (command) => {
      expect(bash(command).kind).toBe("pass");
    },
  );
});

describe("Bash recursive search", () => {
  it("rewrites grep -r, rg and ag with exclusions and leaves single-file greps alone", () => {
    const g = bash("grep -rn TODO src") as { input: { command: string } };
    expect(g.kind).toBe("rewrite");
    expect(g.input.command).toMatch(/^grep --exclude=\.env --exclude='\.env\.\*' .* -rn TODO src$/);
    const r = bash("rg -i password") as { input: { command: string } };
    expect(r.input.command).toMatch(/^rg -g '!\{\.env,\.env\.\*,.*\}' -i password$/);
    expect(bash("rg TODO | head -3").kind).toBe("rewrite");
    expect(bash("grep TODO src/a.ts").kind).toBe("pass");
    expect(bash("rg TODO -g '!.env*'").kind).toBe("pass");
    expect(bash("grep -r TODO --exclude=.env .").kind).toBe("pass");
  });
});

describe("hook output", () => {
  it("prints nothing for pass, a deny decision with reason, an allow with updatedInput for rewrite", () => {
    expect(hookOutput({ kind: "pass" })).toBeUndefined();
    const deny = JSON.parse(hookOutput(bash("cat .env"))!);
    expect(deny.hookSpecificOutput).toMatchObject({ hookEventName: "PreToolUse", permissionDecision: "deny" });
    expect(deny.hookSpecificOutput.permissionDecisionReason).toMatch(/^secrets-axi: \.env is a Secret File/);
    const allow = JSON.parse(hookOutput(bash("rg x"))!);
    expect(allow.hookSpecificOutput).toMatchObject({ permissionDecision: "allow" });
    expect(allow.hookSpecificOutput.updatedInput.command).toContain("-g '!{.env,");
  });
});
