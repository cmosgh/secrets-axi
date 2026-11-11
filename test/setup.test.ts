import { mkdirSync, mkdtempSync, readFileSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { decode } from "@toon-format/toon";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { setupCommand } from "../src/commands/setup.js";
import {
  claudeDenyRules,
  computeClaudeRemoval,
  computeClaudeUpdate,
  computeCodexRemoval,
  computeCodexUpdate,
  guardStatus,
  installGuard,
  resolveHookCommand,
  uninstallGuard,
} from "../src/setup/index.js";

const CMD = "secrets-axi hook";
const RULES = claudeDenyRules();
type Json = Record<string, unknown>;
const toon = (s: string): Json => decode(s, { strict: true }) as Json;
const fmt = (v: unknown): string => `${JSON.stringify(v, null, 2)}\n`;

describe("claudeDenyRules", () => {
  it("emits basename patterns at any depth and ~/ patterns as written, deduplicated", () => {
    expect(RULES).toContain("Read(./**/.env)");
    expect(RULES).toContain("Read(./**/.env.local)");
    expect(RULES).not.toContain("Read(./**/.env.*)");
    expect(RULES).toContain("Read(./**/*.pem)");
    expect(RULES).toContain("Read(~/.aws/credentials)");
    expect(RULES).toContain("Read(~/.ssh/id_*)");
    expect(new Set(RULES).size).toBe(RULES.length);
    expect(RULES.every((r) => /^Read\((\.\/\*\*\/[^/]+|~\/.+)\)$/.test(r))).toBe(true);
  });
});

describe("computeClaudeUpdate / computeClaudeRemoval", () => {
  it("installs into an empty file, is idempotent and removes back to an empty object", () => {
    const [first, changed] = computeClaudeUpdate("", CMD, RULES);
    expect(changed).toBe(true);
    const settings = JSON.parse(first) as { hooks: { PreToolUse: Array<{ matcher: string; hooks: Json[] }> }; permissions: { deny: string[] } };
    expect(settings.hooks.PreToolUse).toEqual([
      { matcher: "Read|Edit|Write|MultiEdit|NotebookEdit|Grep|Bash", hooks: [{ type: "command", command: CMD, timeout: 5 }] },
    ]);
    expect(settings.permissions.deny).toEqual(RULES);
    expect(first.endsWith("\n")).toBe(true);

    expect(computeClaudeUpdate(first, CMD, RULES)).toEqual([first, false]);
    const [removed, rchanged] = computeClaudeRemoval(first, RULES);
    expect(rchanged).toBe(true);
    expect(JSON.parse(removed)).toEqual({});
    expect(computeClaudeRemoval(removed, RULES)).toEqual([removed, false]);
  });

  const unrelated = {
    model: "opus",
    env: { FOO: "1" },
    permissions: { allow: ["Bash(ls)"], deny: ["Read(./private/**)", "Bash(rm -rf *)"] },
    hooks: {
      PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "./audit.sh" }] }],
      SessionStart: [{ matcher: "", hooks: [{ type: "command", command: "./other.sh" }] }],
    },
  };

  it("keeps unrelated hooks, deny rules and keys; only our additions differ", () => {
    const original = fmt(unrelated);
    const [updated] = computeClaudeUpdate(original, CMD, RULES);
    const parsed = JSON.parse(updated) as typeof unrelated;
    expect(parsed.model).toBe("opus");
    expect(parsed.env).toEqual({ FOO: "1" });
    expect(parsed.permissions.allow).toEqual(["Bash(ls)"]);
    expect(parsed.permissions.deny).toEqual([...unrelated.permissions.deny, ...RULES]);
    expect(parsed.hooks.PreToolUse[0]).toEqual(unrelated.hooks.PreToolUse[0]);
    expect(parsed.hooks.PreToolUse).toHaveLength(2);
    expect(parsed.hooks.SessionStart).toEqual(unrelated.hooks.SessionStart);

    // Uninstall restores the original byte for byte.
    expect(computeClaudeRemoval(updated, RULES)).toEqual([original, true]);
  });

  it("preserves a 4-space indent and a missing trailing newline", () => {
    const original = JSON.stringify({ a: 1 }, null, 4);
    const [updated] = computeClaudeUpdate(original, CMD, RULES);
    expect(updated.startsWith('{\n    "a": 1,')).toBe(true);
    expect(updated.endsWith("\n")).toBe(false);
  });

  it("refreshes a stale command in place and drops duplicate entries of ours", () => {
    const stale = fmt({
      hooks: {
        PreToolUse: [
          { matcher: "Bash", hooks: [{ type: "command", command: "node /old/secrets-axi/dist/bin/secrets-axi.js hook", timeout: 1 }] },
          { matcher: "Bash", hooks: [{ type: "command", command: "secrets-axi hook" }] },
        ],
      },
    });
    const [updated] = computeClaudeUpdate(stale, CMD, []);
    const groups = (JSON.parse(updated) as { hooks: { PreToolUse: Array<{ matcher: string; hooks: Json[] }> } }).hooks.PreToolUse;
    expect(groups).toHaveLength(1);
    expect(groups[0]!.matcher).toBe("Read|Edit|Write|MultiEdit|NotebookEdit|Grep|Bash");
    expect(groups[0]!.hooks).toEqual([{ type: "command", command: CMD, timeout: 5 }]);
  });

  it("does not mistake other hooks mentioning secrets-axi for ours", () => {
    const other = fmt({ hooks: { SessionStart: [{ matcher: "", hooks: [{ type: "command", command: "secrets-axi" }] }] } });
    expect(computeClaudeRemoval(other, RULES)).toEqual([other, false]);
  });

  it("removes only ours after an external edit added hooks, reordered keys and a user deny rule", () => {
    const [installed] = computeClaudeUpdate("", CMD, RULES);
    const edited = JSON.parse(installed) as { hooks: { PreToolUse: Array<{ hooks: Json[] }> }; permissions: { deny: string[] } };
    edited.hooks.PreToolUse[0]!.hooks.push({ type: "command", command: "./mine.sh" });
    edited.permissions.deny.unshift("Read(./keep-me)");
    edited.permissions.deny.push("Read(./**/.env.weird)"); // near-miss of ours, not generated
    const [removed, changed] = computeClaudeRemoval(fmt({ extra: true, ...edited }), RULES);
    expect(changed).toBe(true);
    const out = JSON.parse(removed) as { extra: boolean; hooks: { PreToolUse: Array<{ hooks: Json[] }> }; permissions: { deny: string[] } };
    expect(out.extra).toBe(true);
    expect(out.hooks.PreToolUse[0]!.hooks).toEqual([{ type: "command", command: "./mine.sh" }]);
    expect(out.permissions.deny).toEqual(["Read(./keep-me)", "Read(./**/.env.weird)"]);
  });

  it("rejects invalid JSON and wrong shapes instead of overwriting", () => {
    expect(() => computeClaudeUpdate("{bad", CMD, RULES)).toThrow();
    expect(() => computeClaudeUpdate(fmt({ permissions: { deny: "x" } }), CMD, RULES)).toThrow(/not an array/);
    expect(() => computeClaudeUpdate("[]", CMD, RULES)).toThrow();
  });
});

describe("computeCodexUpdate / computeCodexRemoval", () => {
  it("installs Bash|Edit|Write, is idempotent and keeps other hooks", () => {
    const other = { matcher: "Bash", hooks: [{ type: "command", command: "./x.sh" }] };
    const original = fmt({ hooks: { PreToolUse: [other], SessionStart: [{ matcher: "", hooks: [{ type: "command", command: "./s.sh" }] }] } });
    const [updated, changed] = computeCodexUpdate(original, CMD);
    expect(changed).toBe(true);
    const groups = (JSON.parse(updated) as { hooks: { PreToolUse: unknown[] } }).hooks.PreToolUse;
    expect(groups).toEqual([other, { matcher: "Bash|Edit|Write", hooks: [{ type: "command", command: CMD, timeout: 5 }] }]);
    expect(computeCodexUpdate(updated, CMD)).toEqual([updated, false]);
    expect(computeCodexRemoval(updated)).toEqual([original, true]);
  });

  it("empty file round-trips to {}", () => {
    const [updated] = computeCodexUpdate("", CMD);
    expect(JSON.parse(computeCodexRemoval(updated)[0])).toEqual({});
  });
});

describe("installGuard / guardStatus / uninstallGuard on disk", () => {
  let home: string;
  let proj: string;
  beforeEach(() => {
    home = realpathSync(mkdtempSync(join(tmpdir(), "sax-home-")));
    proj = realpathSync(mkdtempSync(join(tmpdir(), "sax-proj-")));
  });

  it("user scope writes under homeDir, status flips, uninstall removes ours", () => {
    const o = { scope: "user" as const, cwd: proj, homeDir: home };
    expect(guardStatus(o)).toMatchObject({ claude: { installed: false, denyRules: 0 }, codex: { installed: false } });
    mkdirSync(join(home, ".claude"));
    const original = fmt({ permissions: { deny: ["Read(./x)"] } });
    writeFileSync(join(home, ".claude", "settings.json"), original);

    const first = installGuard({ ...o, hookCommand: CMD });
    expect(first.claude.changed && first.codex.changed).toBe(true);
    expect(installGuard({ ...o, hookCommand: CMD })).toMatchObject({ claude: { changed: false }, codex: { changed: false } });
    expect(guardStatus(o)).toMatchObject({ claude: { installed: true, denyRules: RULES.length }, codex: { installed: true } });

    uninstallGuard(o);
    expect(guardStatus(o)).toMatchObject({ claude: { installed: false, denyRules: 0 }, codex: { installed: false } });
    expect(readFileSync(join(home, ".claude", "settings.json"), "utf8")).toBe(original);
  });

  it("project scope writes under cwd and leaves home alone", () => {
    const o = { scope: "project" as const, cwd: proj, homeDir: home };
    installGuard({ ...o, hookCommand: CMD });
    expect(guardStatus(o).claude.path).toBe(join(proj, ".claude", "settings.json"));
    expect(guardStatus(o).codex.path).toBe(join(proj, ".codex", "hooks.json"));
    expect(guardStatus(o).claude.installed).toBe(true);
    expect(guardStatus({ ...o, scope: "user" }).claude.installed).toBe(false);
  });

  it("writes nothing when one file is unparsable", () => {
    mkdirSync(join(home, ".codex"));
    writeFileSync(join(home, ".codex", "hooks.json"), "{bad");
    expect(() => installGuard({ scope: "user", cwd: proj, homeDir: home, hookCommand: CMD })).toThrow(/hooks\.json/);
    expect(guardStatus({ scope: "user", cwd: proj, homeDir: home }).claude.installed).toBe(false);
  });
});

describe("secrets-axi setup", () => {
  const savedHome = process.env["HOME"];
  const savedPath = process.env["PATH"];
  let home: string;
  let proj: string;
  let dist: string;
  beforeEach(() => {
    // Never touch the developer's real agent config.
    home = realpathSync(mkdtempSync(join(tmpdir(), "sax-home-")));
    proj = realpathSync(mkdtempSync(join(tmpdir(), "sax-proj-")));
    process.env["HOME"] = home;
    const bin = join(home, "secrets-axi", "dist", "bin");
    mkdirSync(bin, { recursive: true });
    dist = join(bin, "secrets-axi.js");
    writeFileSync(dist, "");
  });
  afterEach(() => {
    process.env["HOME"] = savedHome;
    process.env["PATH"] = savedPath;
  });
  const run = (args: string[], extra: { execPath?: string } = {}) => setupCommand(args, { cwd: proj, homeDir: home, execPath: dist, ...extra });

  it("hook command is the node form for a dist entrypoint and the bare binary for a global install", () => {
    expect(resolveHookCommand(dist)).toBe(`node ${dist} hook`);
    const globalBin = join(home, "globalbin");
    mkdirSync(globalBin);
    symlinkSync(dist, join(globalBin, "secrets-axi"));
    process.env["PATH"] = `${globalBin}:${savedPath}`;
    expect(resolveHookCommand(join(globalBin, "secrets-axi"))).toBe("secrets-axi hook");
    expect(resolveHookCommand("/usr/bin/other")).toBeUndefined();
    expect(resolveHookCommand(join(home, "secrets-axi", "bin", "secrets-axi.ts"))).toBeUndefined();
  });

  it("status before and after install, install is a no-op on repeat", async () => {
    const before = toon(await run(["status"]));
    expect(before["guard"]).toEqual({ scope: "user", claude_code: "not installed", codex: "not installed", session_start: "not installed" });
    expect(before["sandbox"]).toContain("sandbox.filesystem.denyRead");
    expect(before["help"]).toEqual([expect.stringContaining("secrets-axi setup hooks")]);

    const first = toon(await run(["hooks"]));
    expect(first["guard"]).toMatchObject({ status: "installed", claude_code: `installed (${RULES.length} deny rules)`, codex: "installed", session_start: "installed" });
    expect(first["hook"]).toBe(`node ${dist} hook`);
    expect(toon(await run(["hooks"]))["guard"]).toMatchObject({ status: "already installed (no-op)" });

    const after = toon(await run(["status"]));
    expect(after["help"]).toBeUndefined();
    expect((after["guard"] as Json)["claude_code"]).toBe(`installed (${RULES.length} deny rules)`);

    const settings = JSON.parse(readFileSync(join(home, ".claude", "settings.json"), "utf8")) as { hooks: Record<string, unknown> };
    expect(Object.keys(settings.hooks).sort()).toEqual(["PreToolUse", "SessionStart"]);
  });

  it("uninstall removes only ours, including after an external edit", async () => {
    mkdirSync(join(home, ".claude"));
    const mine = { type: "command", command: "./mine.sh" };
    writeFileSync(
      join(home, ".claude", "settings.json"),
      fmt({ permissions: { deny: ["Read(./keep)"] }, hooks: { PreToolUse: [{ matcher: "Bash", hooks: [mine] }], SessionStart: [{ matcher: "", hooks: [mine] }] } }),
    );
    await run(["hooks"]);

    // External edit: someone appends a hook and a rule to the file after install.
    const path = join(home, ".claude", "settings.json");
    const edited = JSON.parse(readFileSync(path, "utf8")) as { permissions: { deny: string[] }; hooks: { PreToolUse: unknown[] } };
    edited.permissions.deny.push("Read(./also-keep)");
    edited.hooks.PreToolUse.push({ matcher: "Write", hooks: [{ type: "command", command: "./later.sh" }] });
    writeFileSync(path, fmt(edited));

    expect(toon(await run(["uninstall"]))["guard"]).toEqual({ scope: "user", status: "removed" });
    expect(JSON.parse(readFileSync(path, "utf8"))).toEqual({
      permissions: { deny: ["Read(./keep)", "Read(./also-keep)"] },
      hooks: {
        PreToolUse: [{ matcher: "Bash", hooks: [mine] }, { matcher: "Write", hooks: [{ type: "command", command: "./later.sh" }] }],
        SessionStart: [{ matcher: "", hooks: [mine] }],
      },
    });
    expect(toon(await run(["status"]))["guard"]).toMatchObject({ claude_code: "not installed", codex: "not installed", session_start: "not installed" });
    expect(toon(await run(["uninstall"]))["guard"]).toMatchObject({ status: "not installed (no-op)" });
  });

  it("--project installs under the repository and leaves home's Guard config alone", async () => {
    const result = toon(await run(["hooks", "--project"]));
    expect((result["guard"] as Json)["scope"]).toBe("project");
    expect(readFileSync(join(proj, ".claude", "settings.json"), "utf8")).toContain("secrets-axi");
    expect(readFileSync(join(proj, ".codex", "hooks.json"), "utf8")).toContain("Bash|Edit|Write");
    expect(toon(await run(["status"]))["guard"]).toMatchObject({ claude_code: "not installed" });
    const projectStatus = toon(await run(["status", "--project"]));
    expect((projectStatus["guard"] as Json)["claude_code"]).toContain("installed");
    expect(projectStatus["help"]).toBeUndefined();

    expect(toon(await run(["uninstall", "--project"]))["guard"]).toMatchObject({ status: "removed" });
    expect(JSON.parse(readFileSync(join(proj, ".claude", "settings.json"), "utf8"))).toEqual({});
    expect(toon(await run(["status", "--project"]))["help"]).toEqual([expect.stringContaining("setup hooks --project")]);
  });

  it("fails instead of claiming success when not running from an installed binary", async () => {
    await expect(run(["hooks"], { execPath: "/tmp/not-ours.js" })).rejects.toMatchObject({ code: "SETUP_FAILED" });
    expect(guardStatus({ scope: "user", cwd: proj, homeDir: home }).claude.installed).toBe(false);
  });

  it("rejects an unknown action, a missing action and a stray argument as usage errors", async () => {
    await expect(run(["install"])).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
    await expect(run([])).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
    await expect(run(["hooks", "extra"])).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
    await expect(run(["hooks", "--global"])).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
  });
});
