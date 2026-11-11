// Output size guard: every stdout byte costs an agent tokens. Each case's estimate is pinned in
// token-budget.json (fails when it grows past TOLERANCE) and held under a hard cap per output kind.
// Refresh the baseline after an intended change: TOKEN_BUDGET_UPDATE=1 corepack pnpm exec vitest run test/token-budget.test.ts
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { main } from "../src/cli.js";
import { estimateTokens } from "./tokens.js";

const BASELINE = join(dirname(fileURLToPath(import.meta.url)), "token-budget.json");
const TOLERANCE = 0.1;
const UPDATE = process.env["TOKEN_BUDGET_UPDATE"] === "1";

type Kind = "home" | "query" | "hint" | "error";
/** Hard ceilings per output kind, independent of the baseline. */
const CAPS: Record<Kind, number> = { home: 260, query: 220, hint: 130, error: 90 };

interface Case {
  name: string;
  kind: Kind;
  argv: string[];
}

const CASES: Case[] = [
  { name: "home", kind: "home", argv: [] },
  { name: "keys", kind: "query", argv: ["keys", ".env"] },
  { name: "check deny bash", kind: "hint", argv: ["check", "source .env && pnpm dev"] },
  { name: "check deny read", kind: "hint", argv: ["check", "--read", ".env"] },
  { name: "check rewrite", kind: "hint", argv: ["check", "rg TODO"] },
  { name: "check fetch", kind: "hint", argv: ["check", "aws secretsmanager get-secret-value --secret-id prod/db"] },
  { name: "set", kind: "query", argv: ["set", ".env", "FLAG=1"] },
  { name: "policy reveal", kind: "query", argv: ["policy", "reveal"] },
  { name: "error unknown flag", kind: "error", argv: ["keys", ".env", "--bogus"] },
  { name: "error missing file", kind: "error", argv: ["keys", ".env.nope"] },
];

let dir = "";
let home = "";
const measured: Record<string, number> = {};
const baseline: Record<string, number> = UPDATE ? {} : (JSON.parse(readFileSync(BASELINE, "utf8")) as Record<string, number>);

beforeAll(() => {
  dir = realpathSync(mkdtempSync(join(tmpdir(), "secrets-axi-budget-")));
  home = join(dir, "home");
  mkdirSync(join(home, ".config", "secrets-axi"), { recursive: true });
  mkdirSync(join(dir, ".git"));
  writeFileSync(join(dir, ".env"), "NODE_ENV=development\nPORT=3000\nDB_URL=postgres://app:FAKE_pw_1234@localhost/app\nAPI_TOKEN=FAKE_tok_1234567890abcdef\nSMTP_HOST=mail.example.test\nSMTP_PASS=FAKE_smtp_pw_0001\nEMPTY=\n");
  writeFileSync(join(dir, ".env.test"), "PORT=3001\n");
});

afterAll(() => {
  if (UPDATE) writeFileSync(BASELINE, `${JSON.stringify(measured, null, 2)}\n`);
});

async function run(argv: string[]): Promise<string> {
  let stdout = "";
  await main({ argv, cwd: dir, home, userPolicyPath: join(home, ".config", "secrets-axi", "policy.json"), stdout: { write: (c: string) => (stdout += c) } });
  return stdout;
}

describe("token budget", () => {
  for (const c of CASES) {
    it(`${c.name}: within its cap and baseline`, async () => {
      const tokens = estimateTokens(await run(c.argv));
      measured[c.name] = tokens;
      expect(tokens, `${c.name} = ${tokens} tokens, cap ${CAPS[c.kind]}`).toBeLessThanOrEqual(CAPS[c.kind]);
      if (UPDATE) return;
      const pinned = baseline[c.name];
      expect(pinned, `no baseline for '${c.name}' - run with TOKEN_BUDGET_UPDATE=1`).toBeDefined();
      expect(tokens, `${c.name} grew from ${pinned} to ${tokens} tokens (> ${TOLERANCE * 100}%) - trim it or refresh the baseline`).toBeLessThanOrEqual(Math.floor(pinned! * (1 + TOLERANCE)));
    });
  }
});
