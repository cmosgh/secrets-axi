import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
  it("heredoc bodies are data: mentions of .env inside them are neither reads nor commands", () => {
    const cmd = "cd notes && cat > note.md <<'EOF'\nUse `secrets-axi run --env-file .env -- x` instead of `set -a; source .env; set +a`.\ncat .env\nEOF\necho done";
    expect(parseCommand(cmd).map((c) => c.tokens.map((t) => t.text).join(" "))).toEqual(["cd notes", "cat note.md", "echo done"]);
    expect(bash(cmd).kind).toBe("pass");
    expect(bash("cat <<-EOF > out.txt\n\t.env\n\tEOF\ncat .env").kind).toBe("deny");
    expect(bash("cat .env <<EOF\nx\nEOF").kind).toBe("deny");
  });

  it("heredoc bodies that bash executes or expands are not data", () => {
    expect(bash("bash <<EOF\ncat .env\nEOF").kind).toBe("deny");
    expect(bash("sh <<'EOF'\nsource .env; node app.js\nEOF").kind).toBe("deny");
    expect(bash("cat <<EOF\n$(cat .env)\nEOF").kind).toBe("deny");
    expect(bash("cat <<EOF\n`cat .env`\nEOF").kind).toBe("deny");
    expect(bash("cat <<'EOF'\n$(cat .env)\nEOF").kind).toBe("pass");
    expect(bash("python3 - <<EOF\nprint(open('.env').read())\nEOF").kind).toBe("deny");
    expect(bash("node <<'EOF'\nrequire('fs').readFileSync('.env')\nEOF").kind).toBe("deny");
    expect(bash("python3 - <<EOF\nprint('.env is loaded by secrets-axi')\nEOF").kind).toBe("pass");
    expect(bash("cat > README.md <<EOF\nRun secrets-axi run -- x instead of source .env\nEOF").kind).toBe("pass");
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
    "find . -name .env -exec cat {} ;",
    "git diff -- '.env*'",
  ])("denies %s", (command) => {
    expect(bash(command).kind).toBe("deny");
  });

  it("the hint keeps the non-reading part of the command", () => {
    const d = bash("source .env && pnpm dev") as { hint: string };
    expect(d.hint).toContain("`secrets-axi run -- pnpm dev`");
    const d2 = bash("set -a; source .env; set +a; node app.js") as { hint: string };
    expect(d2.hint).toContain("`secrets-axi run -- node app.js`");
    const d3 = bash("cd ~/work/app && grep -c . .env") as { hint: string };
    expect(d3.hint).toContain("`secrets-axi run -- <command>`");
    const d4 = bash("cd app && export FOO=1 && cat .env && pnpm start") as { hint: string };
    expect(d4.hint).toContain("`secrets-axi run -- sh -c 'cd app && export FOO=1 && pnpm start'`");
  });

  it("the Hint runs a command list through sh -c and never mangles shell structure", () => {
    const list = bash("B=x; cat .env && make build && make test") as { hint: string };
    expect(list.hint).toContain("`secrets-axi run -- sh -c 'B=x && make build && make test'`");
    // Reported shape: a standalone source in a line with pipes keeps every operator.
    const piped = bash("ls m/ | grep -i spare; set -a; source .secrets.bb >/dev/null 2>&1; set +a; bb-axi pr view 1 2>&1 | head -30; git fetch -q origin stage && git log -3") as { hint: string };
    expect(piped.hint).toContain("`secrets-axi run --env-file .secrets.bb -- sh -c 'ls m/ | grep -i spare; bb-axi pr view 1 2>&1 | head -30; git fetch -q origin stage && git log -3'`");
    for (const command of [
      "cat .env | grep KEY; make",
      "cat .env; (cd w && npx husky; git log -1)",
      "echo $(cat .env) && make",
      "for f in a b; do cat .env; done",
      "B=x; cat .env",
    ]) {
      expect((bash(command) as { hint: string }).hint, command).toContain("`secrets-axi run -- <command>`");
    }
  });

  it.each([
    "docker run --env-file .env app",
    "docker compose --env-file .env.staging up",
    "dotenv -e .env.test -- vitest",
    "dotenvx run -f .env -- node app.js",
    "op run --env-file=.env -- pnpm start",
    "ls -la .env",
    "rm .env.bak",
    "cp .env .claude/worktrees/x/.env",
    "W=.claude/worktrees/X && cp .env $W/.env && cp .env.e2e $W/.env.e2e && (cd $W && npx husky)",
    "install -m 600 .env /srv/app/.env",
    "mv .env.local .env.local.bak",
    "ln -s ../../.env apps/web/.env",
    "cp .env.local apps/",
    "git grep -n foo -- 'tools/**' 'scripts/**'",
    "git ls-files '*'",
    'find apps -name "route-authz*" -not -path "*/node_modules/*"',
    "find . -name .env",
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

  it("a glob is a read when a real match is a Secret File; an unlistable directory counts when it could match one", () => {
    const dir = mkdtempSync(join(tmpdir(), "sx-glob-"));
    for (const d of ["prs", "certs"]) mkdirSync(join(dir, d));
    writeFileSync(join(dir, "prs", "PR-LIST.md"), "x");
    writeFileSync(join(dir, "prs", "rows.json"), "{}");
    writeFileSync(join(dir, "certs", "server.pem"), "x");
    writeFileSync(join(dir, "certs", "README"), "x");
    writeFileSync(join(dir, ".env"), "A=1\n");
    const at = (command: string): string => decide(call("Bash", { command }, dir), BUILTIN, { home: HOME }).kind;
    expect(at("cat DECISIONS.md prs/* 2>/dev/null | sort -u > out.txt")).toBe("pass");
    expect(at("cat *")).toBe("pass");
    expect(at("cat .env*")).toBe("deny");
    expect(at("cat certs/*")).toBe("deny");
    expect(at("head certs/*.pem")).toBe("deny");
    expect(at("cat missing/*")).toBe("deny");
    rmSync(dir, { recursive: true, force: true });
  });

  it("the suggested run loads exactly the Secret Files the command read", () => {
    const dir = mkdtempSync(join(tmpdir(), "sx-hint-"));
    const at = (command: string): string => (decide(call("Bash", { command }, dir), BUILTIN, { home: HOME }) as { hint: string }).hint;
    expect(at("set -a; source .secrets.atlassian; set +a; python3 loop-watch.py triage")).toContain("`secrets-axi run --env-file .secrets.atlassian -- python3 loop-watch.py triage`");
    writeFileSync(join(dir, ".env"), "A=1\n");
    expect(at("set -a; source .secrets.atlassian; set +a; python3 loop-watch.py triage")).toContain("`secrets-axi run --env-file .secrets.atlassian -- python3 loop-watch.py triage`");
    expect(at("source .env && source .env.local && pnpm dev")).toContain("`secrets-axi run --env-file .env --env-file .env.local -- pnpm dev`");
    expect(at("source .env && pnpm dev")).toContain("`secrets-axi run -- pnpm dev`");
    expect(at("cat certs/server.pem && node x.js")).toContain("`secrets-axi run -- node x.js`");
    rmSync(dir, { recursive: true, force: true });
  });

  it("backtick substitutions inside double quotes are commands", () => {
    expect(bash('echo "x `cat .env` y"').kind).toBe("deny");
    expect(bash("echo 'x `cat .env` y'").kind).toBe("pass");
    expect(bash('git commit -m "use `secrets-axi run` instead"').kind).toBe("pass");
  });

  it("git exclude pathspecs are not reads; a command after a shell keyword is judged by its own program", () => {
    expect(bash(`git grep -n "foo" -- '*.js' ':!**/spec/**' | grep -v bar | head -12`).kind).toBe("pass");
    expect(bash("git grep foo -- . ':(exclude).env' ':^.env.local'").kind).toBe("pass");
    expect(bash("git show :.env").kind).toBe("deny");
    expect(bash("git grep foo -- ':(glob).env'").kind).toBe("deny");
    expect(bash("for r in a b; do secrets-axi run --env-file .env -- node x.js; done").kind).toBe("pass");
    expect(bash("if true; then secrets-axi run --env-file .env -- node x.js; fi").kind).toBe("pass");
    expect(bash("for r in a b; do cat .env; done").kind).toBe("deny");
    expect(bash("while true; do source .env; done").kind).toBe("deny");
    expect(bash("! cat .env").kind).toBe("deny");
  });

  it("glob tokens that could name a Secret File are reads; dot-only names are not key files", () => {
    expect(bash("cat .env*").kind).toBe("deny");
    expect(bash("head certs/*.pem").kind).toBe("deny");
    expect(bash("grep -r X --include=.env* .").kind).toBe("deny");
    expect(bash("rg -g '.env*' TOKEN").kind).toBe("deny");
    expect(bash("rg --glob=.env FAKE").kind).toBe("deny");
    expect(bash("rg -g=.env FAKE").kind).toBe("deny");
    expect(bash("rg -g .env FAKE").kind).toBe("deny");
    expect(bash("secrets-axi run -- secrets-axi run -- cat .env").kind).toBe("deny");
    expect(bash("jq .key data.json").kind).toBe("pass");
    expect(bash("cat src/*.ts").kind).toBe("pass");
  });

  it("a consumer that takes the file only as its flag value does not excuse other reads", () => {
    expect(bash("docker run --env-file .env app && cat .env").kind).toBe("deny");
    expect(bash("docker cp .env app:/x").kind).toBe("deny");
    expect(bash("cp .env /dev/stdout").kind).toBe("deny");
    expect(bash("cp .env.local /dev/fd/1").kind).toBe("deny");
    expect(bash("cp .env x/.env && cat x/.env").kind).toBe("deny");
  });
});

describe("Bash over ssh", () => {
  it("judges each command of the remote line and names the remote file", () => {
    const d = bash(`ssh -o ConnectTimeout=10 host1 'sudo -n -u u crontab -l 2>/dev/null | grep -c x; grep -oE "^(MODE|TOKENS?)" /apps/x/.env'`) as { kind: string; file: string; hint: string };
    expect(d.kind).toBe("deny");
    expect(d.file).toBe("/apps/x/.env");
    expect(d.hint).toContain("host1:/apps/x/.env is a Secret File on a remote host");
    expect(d.hint).toContain("`ssh host1 npx -y secrets-axi keys /apps/x/.env`");
    expect(d.hint).not.toContain("--env-file");
    expect(bash("ssh -p 22 host1 cat .env").kind).toBe("deny");
    expect(bash("ssh host1 aws secretsmanager get-secret-value --secret-id p/db").kind).toBe("deny");
  });
  it.each(["ssh host1 npx -y secrets-axi keys /apps/x/.env", "ssh host1 'rm /apps/x/.env.bak'", "ssh host1 uptime", "ssh host1", "npx -y secrets-axi keys .env"])("passes %s", (command) => {
    expect(bash(command).kind).toBe("pass");
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
  it("a keychain read points at run --keychain with the service, account and variable", () => {
    const d = bash('DB_PW="$(security find-generic-password -s mysql-axi -a develop -w)" npm run cli') as { hint: string };
    expect(d.hint).toContain("`secrets-axi run --keychain mysql-axi/develop=DB_PW -- <command>`");
    expect((bash("security find-generic-password -s svc -a me -w") as { hint: string }).hint).toContain("--keychain svc/me=<NAME>");
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
    expect(bash("rg TODO -g '!.env*'").kind).toBe("rewrite");
    expect(bash("grep -r TODO --exclude=foo .").kind).toBe("rewrite");
    expect(bash("grep -r TODO --exclude=.env .").kind).toBe("rewrite");
    expect(bash("rg TODO -g '!{.env,.env.*,*.pem}'").kind).toBe("rewrite");
    expect(bash("rg TODO -g '!*'").kind).toBe("pass");
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
