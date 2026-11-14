import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseEnv, setKey, shapeOf, unsetKey } from "../src/env.js";
import { MaskStream, maskTable, maskText } from "../src/mask.js";
import { BUILTIN, loadPolicy, secretFilePattern } from "../src/policy.js";

const FAKE_TOKEN = "FAKE_tok_1234567890abcdef";

describe("env parser", () => {
  it("reads plain, exported, quoted, multi-line and commented assignments; last wins", () => {
    const text = ['# c', 'A=1', 'export B="two words" # trailing', "C='x#y'", 'D="l1\\nl2"', 'E="multi', 'line"', 'A=3', 'F=', 'bad line', 'G=a=b'].join("\n");
    const env = Object.fromEntries(parseEnv(text).map((e) => [e.key, [e.value, e.line]]));
    expect(env).toEqual({ A: ["3", 8], B: ["two words", 3], C: ["x#y", 4], D: ["l1\nl2", 5], E: ["multi\nline", 6], F: ["", 9], G: ["a=b", 11] });
  });

  it("shapes never contain the value", () => {
    expect(shapeOf("")).toBe("empty");
    expect(shapeOf("3000")).toBe("len 4 digits");
    expect(shapeOf("deadbeefcafe1234")).toBe("len 16 hex");
    expect(shapeOf("postgres://u:p@h/db")).toBe("len 19 url with credentials");
    expect(shapeOf(FAKE_TOKEN)).toBe("len 25 alnum");
    expect(shapeOf("true")).toBe("boolean");
    expect(shapeOf("-----BEGIN RSA PRIVATE KEY-----\nabc")).toBe("pem block");
  });

  it("set replaces in place keeping other bytes, appends new keys, unset removes every assignment", () => {
    const dir = mkdtempSync(join(tmpdir(), "secrets-axi-env-"));
    const file = join(dir, ".env");
    writeFileSync(file, "# head\nexport A=1\nB=2\n\nA=old\n");
    expect(setKey(file, "A", "new value")).toEqual({ key: "A", action: "replaced", line: 5 });
    expect(readFileSync(file, "utf8")).toBe('# head\nexport A=1\nB=2\n\nA="new value"\n');
    expect(setKey(file, "C", "x")).toEqual({ key: "C", action: "set", line: 6 });
    expect(readFileSync(file, "utf8")).toBe('# head\nexport A=1\nB=2\n\nA="new value"\nC=x\n');
    expect(unsetKey(file, "A")).toEqual({ key: "A", action: "removed", line: 2 });
    expect(readFileSync(file, "utf8")).toBe("# head\nB=2\n\nC=x\n");
    expect(unsetKey(file, "ZZ")).toEqual({ key: "ZZ", action: "absent", line: 0 });
  });
});

describe("masking", () => {
  const env = new Map([
    ["TOKEN", FAKE_TOKEN],
    ["SHORT", "ab"],
    ["PREFIX", "FAKE_tok"],
    ["PORT", "3000"],
  ]);
  it("replaces values by name, longest first, skipping short ones", () => {
    const table = maskTable(env);
    expect(table.map((t) => t.replacement)).toEqual(["<TOKEN>", "<PREFIX>", "<PORT>"]);
    expect(maskText(`Authorization: Bearer ${FAKE_TOKEN} on :3000 ab`, table)).toBe("Authorization: Bearer <TOKEN> on :<PORT> ab");
  });
  it("skips plain config literals like true/false", () => {
    const table = maskTable(new Map([["TESTING_MODE", "true"], ["FLAG", "Disabled"], ["TOKEN", FAKE_TOKEN]]));
    expect(table.map((t) => t.replacement)).toEqual(["<TOKEN>"]);
    expect(maskText(`true means create; ${FAKE_TOKEN}`, table)).toBe("true means create; <TOKEN>");
  });
  it("catches a value split across chunks", async () => {
    const stream = new MaskStream(maskTable(env));
    const chunks: string[] = [];
    stream.on("data", (c: Buffer) => chunks.push(c.toString()));
    const text = `line one\nkey=${FAKE_TOKEN}\nend`;
    const cut = text.indexOf(FAKE_TOKEN) + 7;
    stream.write(text.slice(0, cut));
    stream.write(text.slice(cut));
    await new Promise<void>((r) => stream.end(r));
    expect(chunks.join("")).toBe("line one\nkey=<TOKEN>\nend");
  });
});

describe("policy", () => {
  it("built-in patterns classify by basename, home paths by full path, exceptions win", () => {
    const home = "/h";
    expect(secretFilePattern("/r/.env", BUILTIN, "/r", home)).toBe(".env");
    expect(secretFilePattern(".env.production", BUILTIN, "/r", home)).toBe(".env.*");
    expect(secretFilePattern(".env.example", BUILTIN, "/r", home)).toBeUndefined();
    expect(secretFilePattern("~/.aws/credentials", BUILTIN, "/r", home)).toBe("~/.aws/credentials");
    expect(secretFilePattern("/h/.ssh/id_rsa", BUILTIN, "/r", home)).toBe("~/.ssh/id_*");
    expect(secretFilePattern("/r/.ssh/id_rsa", BUILTIN, "/r", home)).toBe("id_rsa*");
    expect(secretFilePattern("src/env.ts", BUILTIN, "/r", home)).toBeUndefined();
  });

  it("layers: user may add and remove, repo may add only; broken files are skipped and reported", () => {
    const dir = mkdtempSync(join(tmpdir(), "secrets-axi-policy-"));
    const user = join(dir, "policy.json");
    writeFileSync(user, JSON.stringify({ reveal: ["API_BASE_URL"], remove: { secretFiles: ["*.key"] } }));
    const repo = join(dir, "repo");
    writeFileSync(join(dir, ".secrets-axi.json"), JSON.stringify({ secretFiles: ["config/*.secret"], remove: { secretFiles: [".env"] }, envFiles: [".env", ".env.local"] }));
    const load = loadPolicy(dir, { userPath: user });
    expect(load.policy.reveal).toContain("API_BASE_URL");
    expect(load.policy.secretFiles).not.toContain("*.key");
    expect(load.policy.secretFiles).toContain(".env");
    expect(load.policy.secretFiles).toContain("config/*.secret");
    expect(load.origin.secretFiles.get("config/*.secret")).toBe("repo");
    expect(load.policy.envFiles).toEqual([".env", ".env.local"]);
    expect(load.repoPath).toBe(join(dir, ".secrets-axi.json"));
    void repo;
    writeFileSync(user, "{not json");
    const broken = loadPolicy(dir, { userPath: user });
    expect(broken.broken).toEqual([user]);
    expect(broken.policy.secretFiles).toContain("*.key");
  });
});
