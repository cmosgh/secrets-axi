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
  for (const wt of ["a", "b", "c"]) {
    mkdirSync(join(dir, ".claude", "worktrees", wt, "apps"), { recursive: true });
    writeFileSync(join(dir, ".claude", "worktrees", wt, ".env"), "PORT=3000\n");
    writeFileSync(join(dir, ".claude", "worktrees", wt, "apps", ".env"), "PORT=3000\n"); // below the root: not scanned
  }
  writeFileSync(join(dir, ".claude", "worktrees", "b", ".env.local"), "PORT=3000\n");
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
    const keychain = ({ service, account }: { service: string; account: string }): string => {
      if (service === "fake-svc" && account === "dev") return "FAKE_KEYCHAIN_PASSWORD_1";
      throw new Error(`no item ${service}/${account}`);
    };
    await main({ argv, cwd: dir, home, userPolicyPath: join(home, ".config", "secrets-axi", "policy.json"), stdout: { write: (c: string) => (stdout += c) }, io: { stdout: out, stderr: err }, keychain });
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
    expect(data["secret_files"]).toEqual([
      { path: ".env", keys: 6, tracked: false },
      { path: ".env.test", keys: 1, tracked: false },
    ]);
    expect(data["worktree_copies"]).toEqual([
      { path: ".env", worktrees: 3, root: ".claude/worktrees" },
      { path: ".env.local", worktrees: 1, root: ".claude/worktrees" },
    ]);
    expect(data["source"]).toBe("dotenv (.env)");
    expect(data["not_loaded"]).toEqual([".env.test"]);
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
    const stray = await sx("set", ".env", "K", `${FAKE_PW}x`);
    expect(stray.exitCode).toBe(2);
    expect(stray.stdout).not.toContain(FAKE_PW);
    const cols = toon((await sx("keys", ".env", "--fields", "line")).stdout)["keys"] as Payload[];
    expect(Object.keys(cols[0]!)).toEqual(["name", "line"]);
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
    expect(ok.stdout).toBe("<API_TOKEN> 3000 undefined\n"); // PORT is a Reveal Key: not masked
    expect(ok.stderr).toContain("secrets-axi: 6 variables (6 from .env) - output masked");
    const test = await sx("run", "--env-file", ".env.test", "--quiet", "--", "node", "-e", "console.log(process.env.PORT, process.env.API_TOKEN); console.error('port ' + process.env.PORT); process.exit(3)");
    expect(test.exitCode).toBe(3);
    expect(test.stdout).toBe("3001 undefined\n");
    expect(test.stderr).toBe("port 3001\n");
    const none = await sx("run", "--source", "none", "--quiet", "--", "node", "-e", "console.log(process.env.API_TOKEN)");
    expect(none.stdout).toBe("undefined\n");
    const missing = await sx("run", "--", "definitely-not-a-command-xyz");
    expect(missing.exitCode).toBe(1);
    expect(missing.stdout).toContain("command not found");
    const kc = await sx("run", "--source", "none", "--keychain", "fake-svc/dev=DB_PASSWORD", "--", "node", "-e", "console.log(process.env.DB_PASSWORD)");
    expect(kc.stdout).toBe("<DB_PASSWORD>\n");
    expect(kc.stderr).toContain("keychain fake-svc/dev");
    const badSpec = await sx("run", "--keychain", "fake-svc/dev", "--", "node", "-e", "1");
    expect(badSpec.exitCode).toBe(2);
    expect(badSpec.stdout).toContain("<service>/<account>=NAME");
    const noSep = await sx("run", "pnpm", "test");
    expect(noSep.exitCode).toBe(2);
    const childFlags = await sx("run", "--quiet", "--", "node", "-e", "console.log(process.argv.slice(1).join(' '))", "--", "--json", "--help");
    expect(childFlags.stdout).toBe("--json --help\n");
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
