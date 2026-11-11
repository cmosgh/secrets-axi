import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { describe, expect, it } from "vitest";

/**
 * The hook runs on every agent tool call. Wall time of `node dist/bin/secrets-axi.js hook`
 * against bare `node -e ""` must stay small: the budget is what the guard adds over Node startup.
 */
// Shared CI runners are noisy (35 ms seen for a 20 ms local run); the strict pin is the local one.
const BUDGET_MS = process.env["CI"] ? 80 : 30;
const ROUNDS = 9;
const BIN = new URL("../dist/bin/secrets-axi.js", import.meta.url).pathname;

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)]!;
}

function time(args: string[], input: string): number {
  const start = performance.now();
  const result = spawnSync(process.execPath, args, { input, encoding: "utf8" });
  if (result.status !== 0) throw new Error(result.stderr);
  return performance.now() - start;
}

describe.skipIf(!existsSync(BIN))("hook latency", () => {
  it(`adds under ${BUDGET_MS} ms (median) over bare node startup`, () => {
    const payload = JSON.stringify({ tool_name: "Bash", tool_input: { command: "source .env && pnpm dev" }, cwd: process.cwd() });
    time([BIN, "hook"], payload); // warm the disk cache
    const bare = median(Array.from({ length: ROUNDS }, () => time(["-e", ""], "")));
    const hook = median(Array.from({ length: ROUNDS }, () => time([BIN, "hook"], payload)));
    expect(hook - bare).toBeLessThan(BUDGET_MS);
  });
});
