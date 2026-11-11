import { mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough, Readable } from "node:stream";
import { decode } from "@toon-format/toon";
import { beforeAll, describe, expect, it } from "vitest";
import { main } from "../src/cli.js";
import { runHook } from "../src/hook/entry.js";

type Payload = Record<string, unknown>;
const FAKE_PW = "FAKE_pw_9f8e7d6c";
const FAKE_TOKEN = "FAKE_tok_1234567890abcdef";
const SECRETS = [FAKE_PW, FAKE_TOKEN];

interface Run {
  stdout: string;
  stderr: string;
  exitCode: number;
}

function fixture(): { dir: string; home: string } {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "secrets-axi-cmd-")));
  const home = join(dir, "home");
  mkdirSync(join(home, ".config", "secrets-axi"), { recursive: true });
  mkdirSync(join(dir, ".git"));
  writeFileSync(join(dir, ".env"), `NODE_ENV=development\nPORT=3000\nDB_URL=postgres://app:${FAKE_PW}@localhost/app\nAPI_TOKEN=${FAKE_TOKEN}\nEMPTY=\n`);
  writeFileSync(join(dir, ".env.example"), "NODE_ENV=\nPORT=\n");
  writeFileSync(join(dir, ".env.test"), "PORT=3001\n");
  mkdirSync(join(dir, "src"));
  writeFileSync(join(dir, "src", "app.js"), "console.log(process.env.API_TOKEN, process.env.PORT, process.env.EXTRA);\n");
  return { dir, home };
}

function runner(dir: string, home: string) {
  return async (...argv: string[]): Promise<Run> => {
    let stdout = "";
    let stderr = "";
    const out = new PassThrough();
    const err = new PassThrough();
    out.on("data", (c: Buffer) => (stdout += c.toString()));
    err.on("data", (c: Buffer) => (stderr += c.toString()));
    const before = process.exitCode;
    process.exitCode = 0;
    await main({ argv, cwd: dir, home, userPolicyPath: join(home, ".config", "secrets-axi", "policy.json"), stdout: { write: (c: string) => (stdout += c) }, io: { stdout: out, stderr: err } });
    const exitCode = Number(process.exitCode ?? 0);
    process.exitCode = before;
    return { stdout, stderr, exitCode };
  };
}

const toon = (text: string): Payload => decode(text.replace(/\n---\n[\s\S]*$/, ""), { strict: false }) as Payload;

describe("secrets-axi commands", () => {
  let dir: string;
  let home: string;
  let sx: (...argv: string[]) => Promise<Run>;
  beforeAll(() => {
    ({ dir, home } = fixture());
    sx = runner(dir, home);
  });

  it("no output of any command contains a secret value", async () => {
    const outputs = await Promise.all([sx(), sx("keys", ".env"), sx("check", "cat .env"), sx("policy"), sx("set", ".env", "FEATURE_X=true"), sx("keys", ".env", "--fields", "all"), sx("keys", ".env", "--json")]);
    for (const { stdout, stderr } of outputs) for (const secret of SECRETS) expect(stdout + stderr).not.toContain(secret);
  });

  it("home lists Secret Files with key counts, the source and the env files not loaded", async () => {
    const data = toon((await sx()).stdout);
    expect(data["secret_files"]).toEqual([".env (6 keys)", ".env.test (1 keys)"]);
    expect(data["source"]).toBe("dotenv (.env)");
    expect(data["not_loaded"]).toBe(".env.test");
    expect(data["guard"]).toBe("not installed");
  });

  it("keys shows names and shapes, reveals only Reveal Keys", async () => {
    const data = toon((await sx("keys", ".env")).stdout);
    expect(data["keys"]).toEqual([
      { name: "NODE_ENV", shape: "len 11 alnum" },
      { name: "PORT", shape: "len 4 digits" },
      { name: "DB_URL", shape: "len 45 url with credentials" },
      { name: "API_TOKEN", shape: "len 25 alnum" },
      { name: "EMPTY", shape: "empty" },
      { name: "FEATURE_X", shape: "boolean" },
    ]);
    expect(data["revealed"]).toEqual({ NODE_ENV: "development", PORT: "3000" });
  });

  it("set and unset edit in place and report the key only", async () => {
    expect(toon((await sx("set", ".env", "NEW_ONE=hello world")).stdout)).toMatchObject({ file: ".env", key: "NEW_ONE", action: "set" });
    expect(readFileSync(join(dir, ".env"), "utf8")).toContain('NEW_ONE="hello world"\n');
    expect(toon((await sx("unset", ".env", "NEW_ONE")).stdout)).toMatchObject({ key: "NEW_ONE", action: "removed" });
    expect(readFileSync(join(dir, ".env"), "utf8")).not.toContain("NEW_ONE");
    const bad = await sx("set", ".env", "no-equals");
    expect(bad.exitCode).toBe(2);
  });

  it("check explains deny, rewrite and pass with the policy rule", async () => {
    expect(toon((await sx("check", "cat .env | grep DB")).stdout)).toMatchObject({ decision: "deny", rule: "secretFiles:.env", file: ".env" });
    expect(toon((await sx("check", "--read", "~/.aws/credentials")).stdout)).toMatchObject({ decision: "deny", file: "~/.aws/credentials" });
    expect(toon((await sx("check", "rg TODO src")).stdout)).toMatchObject({ decision: "rewrite", rule: "recursiveSearch" });
    expect(toon((await sx("check", "docker run --env-file .env app")).stdout)).toMatchObject({ decision: "pass" });
  });

  it("policy prints origins; add writes the user layer and it takes effect", async () => {
    expect((toon((await sx("policy", "reveal")).stdout)["reveal"] as string[])).toContain("NODE_ENV");
    await sx("policy", "add", "reveal", "DB_URL");
    const user = JSON.parse(readFileSync(join(home, ".config", "secrets-axi", "policy.json"), "utf8")) as Payload;
    expect(user).toEqual({ reveal: ["DB_URL"] });
    const after = toon((await sx("policy", "reveal")).stdout)["reveal"] as string[];
    expect(after).toContain("DB_URL (user)");
    await sx("policy", "drop", "reveal", "DB_URL");
    await sx("policy", "add", "--remove", "consumers", "echo");
    expect(toon((await sx("check", "echo .env")).stdout)).toMatchObject({ decision: "deny" });
    await sx("policy", "drop", "--remove", "consumers", "echo");
  });

  it("run injects the env, masks values in stdout and stderr, keeps the exit code, honours --env-file and --source none", async () => {
    const ok = await sx("run", "--", "node", "src/app.js");
    expect(ok.exitCode).toBe(0);
    expect(ok.stdout).toBe("<API_TOKEN> <PORT> undefined\n");
    expect(ok.stderr).toContain("secrets-axi: 6 variables (6 from .env) - output masked");
    const test = await sx("run", "--env-file", ".env.test", "--quiet", "--", "node", "-e", "console.log(process.env.PORT, process.env.API_TOKEN); console.error('port ' + process.env.PORT); process.exit(3)");
    expect(test.exitCode).toBe(3);
    expect(test.stdout).toBe("<PORT> undefined\n");
    expect(test.stderr).toBe("port <PORT>\n");
    const none = await sx("run", "--source", "none", "--quiet", "--", "node", "-e", "console.log(process.env.API_TOKEN)");
    expect(none.stdout).toBe("undefined\n");
    const missing = await sx("run", "--", "definitely-not-a-command-xyz");
    expect(missing.exitCode).toBe(1);
    expect(missing.stdout).toContain("command not found");
    const noSep = await sx("run", "pnpm", "test");
    expect(noSep.exitCode).toBe(2);
  });

  it("the hook entry denies from stdin JSON and stays silent on pass or garbage", async () => {
    const hook = async (payload: unknown): Promise<string> => {
      let out = "";
      await runHook(Readable.from([typeof payload === "string" ? payload : JSON.stringify(payload)]), { write: (s: string) => (out += s) });
      return out;
    };
    const deny = JSON.parse(await hook({ hook_event_name: "PreToolUse", tool_name: "Read", tool_input: { file_path: join(dir, ".env") }, cwd: dir }));
    expect(deny.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(await hook({ tool_name: "Read", tool_input: { file_path: join(dir, "src/app.js") }, cwd: dir })).toBe("");
    expect(await hook("{not json")).toBe("");
    const rewrite = JSON.parse(await hook({ tool_name: "Grep", tool_input: { pattern: "x", path: dir }, cwd: dir }));
    expect(rewrite.hookSpecificOutput.updatedInput.glob).toMatch(/^!\{\.env,/);
  });
});
