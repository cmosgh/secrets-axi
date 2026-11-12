// Guard decisions: deterministic, from the Policy and the literal call. Node builtins only.
import { existsSync, readdirSync, statSync } from "node:fs";
import { basename, isAbsolute, relative, resolve } from "node:path";
import { basenamePatterns, expandHome, globToRegExp, sampleNames, secretFilePattern, type Policy } from "../policy.js";
import { parseCommand, programOf, type SimpleCommand, type Token } from "./tokenize.js";

export type ToolName = "Read" | "Edit" | "Write" | "MultiEdit" | "NotebookEdit" | "Grep" | "Glob" | "Bash" | string;

export interface ToolCall {
  tool: ToolName;
  input: Record<string, unknown>;
  cwd: string;
}

export type Decision =
  | { kind: "pass" }
  | { kind: "deny"; rule: string; file?: string; hint: string }
  | { kind: "rewrite"; rule: string; input: Record<string, unknown>; note: string };

export interface GuardOptions {
  home?: string;
}

/** Per search tool: when it is recursive and how to exclude a set of basename patterns (already shell-quoted). */
const RECURSIVE_SEARCH: Record<string, { always: boolean; flags: string[]; exclude: (patterns: string[]) => string }> = {
  grep: { always: false, flags: ["-r", "-R", "--recursive", "--dereference-recursive", "--include", "--exclude-dir"], exclude: (ps) => ps.map((p) => `--exclude=${quote(p)}`).join(" ") },
  egrep: { always: false, flags: ["-r", "-R", "--recursive"], exclude: (ps) => ps.map((p) => `--exclude=${quote(p)}`).join(" ") },
  fgrep: { always: false, flags: ["-r", "-R", "--recursive"], exclude: (ps) => ps.map((p) => `--exclude=${quote(p)}`).join(" ") },
  rg: { always: true, flags: [], exclude: (ps) => `-g ${quote(`!{${ps.join(",")}}`)}` },
  ag: { always: true, flags: [], exclude: (ps) => ps.map((p) => `--ignore ${quote(p)}`).join(" ") },
  ack: { always: true, flags: [], exclude: (ps) => ps.map((p) => `--ignore-file=${quote(`match:${globToAckRegex(p)}`)}`).join(" ") },
};

function globToAckRegex(p: string): string {
  return `/^${p.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$/`;
}

/** Display form of a path for Hints: relative to cwd when below it, `~/...` for home, else absolute. */
export function display(path: string, cwd: string, home: string | undefined): string {
  const abs = resolve(cwd, expandHome(path, home));
  const rel = relative(cwd, abs);
  const underCwd = rel !== "" && !rel.startsWith("..") && !isAbsolute(rel);
  const underHome = home !== undefined && abs.startsWith(`${home}/`);
  // `~/...` wins for home files even when (as in tests) the home sits inside the repository.
  if (underHome && (!underCwd || home.startsWith(`${cwd}/`))) return `~${abs.slice(home.length)}`;
  if (underCwd) return rel;
  return abs;
}

export function decide(call: ToolCall, policy: Policy, options: GuardOptions = {}): Decision {
  const home = options.home;
  switch (call.tool) {
    case "Read":
    case "Edit":
    case "Write":
    case "MultiEdit":
    case "NotebookEdit":
      return fileTool(call, policy, home);
    case "Grep":
      return grepTool(call, policy, home);
    case "Bash":
      return bash(call, policy, home);
    default:
      return { kind: "pass" };
  }
}

function fileTool(call: ToolCall, policy: Policy, home: string | undefined): Decision {
  const path = typeof call.input["file_path"] === "string" ? call.input["file_path"] : typeof call.input["notebook_path"] === "string" ? call.input["notebook_path"] : undefined;
  if (!path) return { kind: "pass" };
  const pattern = secretFilePattern(path, policy, call.cwd, home);
  if (!pattern) return { kind: "pass" };
  const file = display(path, call.cwd, home);
  if (call.tool === "Read") {
    return { kind: "deny", rule: `secretFiles:${pattern}`, file, hint: readHint(file) };
  }
  return { kind: "deny", rule: `secretFiles:${pattern}`, file, hint: editHint(file) };
}

function readHint(file: string): string {
  return `${file} is a Secret File - its values must not enter the transcript. Run \`secrets-axi keys ${quote(file)}\` for its variable names and shapes, or \`secrets-axi run -- <command>\` to run something with it loaded`;
}

function editHint(file: string): string {
  return `${file} is a Secret File - editing it would echo its values. Run \`secrets-axi set ${quote(file)} KEY=value\` to add or change one variable, \`secrets-axi unset ${quote(file)} KEY\` to remove one`;
}

function grepTool(call: ToolCall, policy: Policy, home: string | undefined): Decision {
  const path = typeof call.input["path"] === "string" ? call.input["path"] : undefined;
  if (path) {
    const pattern = secretFilePattern(path, policy, call.cwd, home);
    if (pattern) {
      const file = display(path, call.cwd, home);
      return { kind: "deny", rule: `secretFiles:${pattern}`, file, hint: readHint(file) };
    }
  }
  const glob = typeof call.input["glob"] === "string" ? call.input["glob"].trim() : "";
  // An explicit include glob already narrows the search; a `.env`-shaped one is the agent asking for the file (deny).
  if (glob !== "") {
    const asks = basenamePatterns(policy).some((p) => glob === p || glob.endsWith(`/${p}`));
    if (asks) return { kind: "deny", rule: `secretFiles:${glob}`, file: glob, hint: readHint(glob) };
    return { kind: "pass" };
  }
  const exclusion = `!{${basenamePatterns(policy).join(",")}}`;
  return { kind: "rewrite", rule: "recursiveSearch", input: { ...call.input, glob: exclusion }, note: `Secret Files excluded from the search (glob ${exclusion})` };
}

function quote(s: string): string {
  return /^[A-Za-z0-9_./~@:+=,-]+$/.test(s) ? s : `'${s.replace(/'/g, "'\\''")}'`;
}

interface Consumer {
  program: string[];
  flag?: string;
}

function parseConsumer(spec: string): Consumer {
  const parts = spec.split(/\s+/);
  const flagAt = parts.findIndex((p) => p.startsWith("-"));
  return flagAt < 0 ? { program: parts } : { program: parts.slice(0, flagAt), flag: parts[flagAt] };
}

const INLINE_CODE: Record<string, string[]> = {
  python: ["-c"],
  python3: ["-c"],
  python2: ["-c"],
  node: ["-e", "--eval", "-p", "--print"],
  bun: ["-e", "--eval", "-p", "--print"],
  deno: ["eval"],
  ruby: ["-e"],
  perl: ["-e", "-E"],
  php: ["-r"],
  osascript: ["-e"],
};

/** String literals of inline code (`python -c '... open(".env") ...'`): each is a path candidate. */
function inlineLiterals(cmd: SimpleCommand, program: string): string[] {
  const flags = INLINE_CODE[program] ?? (cmd.tokens.some((t) => t.heredoc) ? [] : undefined);
  if (!flags) return [];
  const out: string[] = [];
  const words = cmd.tokens.map((t) => t.text);
  for (let i = 0; i < words.length; i++) {
    const viaHeredoc = cmd.tokens[i]!.heredoc === true;
    if (!viaHeredoc && !flags.includes(words[i]!)) continue;
    const code = viaHeredoc ? words[i]! : (words[i + 1] ?? "");
    // A literal with an escape sequence (`"a\nb"`) is text, never a path.
    for (const m of code.matchAll(/(["'`])([^"'`\n]{1,200})\1/g)) if (!/\\[ntr]/.test(m[2]!)) out.push(m[2]!);
    if (program.endsWith("sh")) for (const inner of parseCommand(code)) out.push(...inner.tokens.map((t) => t.text));
  }
  return out;
}

/** Tokens of a command that resolve to Secret Files, with the `--flag=value` form unwrapped. */
function secretTokens(cmd: SimpleCommand, policy: Policy, cwd: string, home: string | undefined, program: string | undefined): Array<{ token: Token; path: string; pattern: string }> {
  const hits: Array<{ token: Token; path: string; pattern: string }> = [];
  const patterns = program ? searchPatterns(cmd, program) : new Set<Token>();
  for (const [i, token] of cmd.tokens.entries()) {
    // `>> .env` writes the file; nothing of it reaches the transcript.
    if (token.output) continue;
    // A search pattern (`grep -E "\.env" f`) matches text; the files come after it.
    if (patterns.has(token)) continue;
    // Interpreter code (a heredoc body, `python -c <code>`) is judged by its string literals below, never as one path.
    if (token.heredoc || (program && INLINE_CODE[program]?.includes(cmd.tokens[i - 1]?.text ?? ""))) continue;
    // The value of an exclusion names what is NOT read: `--exclude=X`, `--ignore X`, `-g '!X'` (a plain `-g X` includes).
    if (exclusionValue(token.text, cmd.tokens[i - 1]?.text) !== undefined) continue;
    // Git exclude pathspecs (`:!x`, `:^x`, `:(exclude)x`) name what is not read, like `--exclude`.
    if (program === "git" && /^:(!|\^|\([^)]*\bexclude\b[^)]*\))/.test(token.text)) continue;
    // Git expands a pathspec like `'scripts/**'` itself, over tracked files; an all-wildcard name targets no Secret File.
    if (program === "git" && /^[^:]*\/[*?]+$|^[*?]+$/.test(token.text)) continue;
    // `find -path X` matches names; without an action that runs something, find only lists paths.
    if (program === "find" && FIND_TESTS.has(cmd.tokens[i - 1]?.text ?? "") && !cmd.tokens.some((t) => FIND_ACTIONS.has(t.text))) continue;
    const candidates = [token.text];
    const eq = token.text.match(/^--?[A-Za-z][\w-]*=(.+)$/);
    if (eq) candidates.push(eq[1]!);
    // `git show HEAD:.env`, `git cat-file -p main:.env`
    if (program === "git") {
      const rev = token.text.match(/^[^:\s]*:(.+)$/);
      if (rev) candidates.push(rev[1]!);
      const magic = token.text.match(/^:\([^)]*\)(.+)$/); // `:(glob).env`, `:(top,icase).env`
      if (magic) candidates.push(magic[1]!);
    }
    for (const path of candidates) {
      if (path.startsWith("-") || path === "" || /^[A-Za-z_][A-Za-z0-9_]*=$/.test(path)) continue;
      const pattern = secretFilePattern(path, policy, cwd, home) ?? globPattern(path, policy, cwd, home);
      if (pattern) {
        hits.push({ token, path, pattern });
        break;
      }
    }
  }
  if (program && hits.length === 0) {
    for (const literal of inlineLiterals(cmd, program)) {
      const pattern = secretFilePattern(literal, policy, cwd, home);
      if (pattern) {
        hits.push({ token: cmd.tokens[0]!, path: literal, pattern });
        break;
      }
    }
  }
  return hits;
}

const SEARCHERS = new Set(["grep", "egrep", "fgrep", "rg", "ag", "ack"]);
/** Options of the searchers whose value is a pattern; `-f`/`--file` names a pattern file and stays a path. */
const PATTERN_FLAGS = new Set(["-e", "--regexp"]);
const SEARCH_VALUED = new Set(["-f", "--file", "-m", "--max-count", "-A", "-B", "-C", "--after-context", "--before-context", "--context", "-d", "-D", "-g", "--glob", "-t", "-T", "--type", "--type-not", "-j", "--threads", "-M", "--label", "--include", "--exclude", "--exclude-dir", "--ignore", "--ignore-file"]);

/** The pattern tokens of a grep-like search: `-e` values, else its first positional. */
function searchPatterns(cmd: SimpleCommand, program: string): Set<Token> {
  const out = new Set<Token>();
  if (!SEARCHERS.has(program)) return out;
  const tokens = cmd.tokens.filter((t) => !t.redirect);
  const start = tokens.findIndex((t) => t.text.replace(/^.*\//, "") === program);
  let explicit = false;
  let first: Token | undefined;
  for (let i = start + 1; i < tokens.length; i++) {
    const w = tokens[i]!.text;
    if (w === "--") {
      if (!explicit && !first) first = tokens[i + 1];
      break;
    }
    const cluster = /^-[A-Za-z0-9]+$/.test(w) ? w.slice(1) : "";
    if (PATTERN_FLAGS.has(w) || (cluster.endsWith("e") && !/\d/.test(cluster))) {
      // `-e PAT`, `-ie PAT`: the next word is a pattern.
      if (tokens[i + 1]) out.add(tokens[++i]!);
      explicit = true;
    } else if (w.startsWith("--regexp=") || (cluster.includes("e") && !/\d/.test(cluster.slice(0, cluster.indexOf("e"))))) {
      explicit = true; // `-eKEY`, `--regexp=KEY`: the pattern is attached.
    } else if (SEARCH_VALUED.has(w) || (cluster.length > 1 && SEARCH_VALUED.has(`-${cluster.at(-1)}`))) i++;
    else if (!w.startsWith("-") && !first) first = tokens[i];
  }
  if (!explicit && first) out.add(first);
  return out;
}

const FIND_TESTS =new Set(["-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename", "-regex", "-iregex", "-lname", "-ilname"]);
const FIND_ACTIONS = new Set(["-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls"]);

const ALWAYS_EXCLUDES =/^(--exclude|--exclude-dir|--ignore|--ignore-file)(=|$)/;
const GLOB_FLAGS = /^(--glob|--iglob|-g)(=|$)/;

/** The pattern an exclusion token (or flag value) excludes, or undefined when the token is not an exclusion. */
function exclusionValue(word: string, prev: string | undefined): string | undefined {
  const eq = word.indexOf("=");
  if (ALWAYS_EXCLUDES.test(word) && eq > 0) return word.slice(eq + 1);
  if (GLOB_FLAGS.test(word) && eq > 0 && word[eq + 1] === "!") return word.slice(eq + 2);
  if (prev !== undefined && !prev.includes("=")) {
    if (ALWAYS_EXCLUDES.test(prev)) return word;
    if (GLOB_FLAGS.test(prev) && word.startsWith("!")) return word.slice(1);
  }
  return undefined;
}

/** Does an exclusion pattern cover every Secret File basename pattern? Only then is a search "already excluded". */
function excludesSecrets(value: string, policy: Policy): boolean {
  const re = globToRegExp(value.replace(/^.*\//, ""));
  return sampleNames(policy).every((name) => re.test(name));
}

/** A glob token (`.env*`, `*.pem`) that could name a Secret File: tested against one sample name per pattern. */
/**
 * A glob token is a read of a Secret File when one of its real matches is one (`prs/*` over markdown passes,
 * `certs/*` over a .pem denies). When the directory cannot be listed here, it counts when it could match one.
 */
function globPattern(token: string, policy: Policy, cwd: string, home: string | undefined): string | undefined {
  if (!/[*?]/.test(token)) return undefined;
  const slash = token.lastIndexOf("/");
  const dir = slash < 0 ? "" : token.slice(0, slash + 1);
  const base = token.slice(slash + 1);
  const re = globToRegExp(base);
  if (!/[*?]/.test(dir)) {
    const entries = listDir(resolve(cwd, expandHome(dir || ".", home)));
    if (entries) {
      // Like the shell, `*` does not expand to dotfiles unless the pattern starts with a dot.
      const names = entries.filter((name) => (base.startsWith(".") || !name.startsWith(".")) && re.test(name));
      for (const name of names) {
        const pattern = secretFilePattern(dir + name, policy, cwd, home);
        if (pattern) return pattern;
      }
      return undefined;
    }
  }
  const patterns = basenamePatterns(policy);
  const at = sampleNames(policy).findIndex((name) => (base.startsWith(".") || !name.startsWith(".")) && re.test(name));
  return at >= 0 ? patterns[at] : undefined;
}

function listDir(dir: string): string[] | undefined {
  try {
    return readdirSync(dir);
  } catch {
    return undefined;
  }
}

/** Tokens after `--` of a `secrets-axi run` as a command of their own: the Runner must not be a way around the Guard. */
function runChild(cmd: SimpleCommand, programIndex: number): SimpleCommand | undefined {
  if (cmd.tokens[programIndex + 1]?.text !== "run") return undefined;
  const sep = cmd.tokens.findIndex((t, i) => i > programIndex && t.text === "--");
  if (sep < 0 || sep === cmd.tokens.length - 1) return undefined;
  const tokens = cmd.tokens.slice(sep + 1);
  return { tokens, start: tokens[0]!.start, end: cmd.end };
}

function isFetch(cmd: SimpleCommand, programIndex: number, policy: Policy): string | undefined {
  const words = cmd.tokens.slice(programIndex).map((t) => t.text);
  const positional = words.filter((w) => !w.startsWith("-"));
  for (const spec of policy.fetchCommands) {
    const parts = spec.split(/\s+/);
    const need = parts.filter((p) => !p.startsWith("-"));
    const flags = parts.filter((p) => p.startsWith("-"));
    const first = positional[0]?.replace(/^.*\//, "");
    if (first !== need[0]) continue;
    // Global options with values (`aws --profile x ssm ...`) sit between: the subcommand words must appear in order, not adjacent.
    let at = 1;
    const inOrder = need.slice(1).every((n) => {
      const found = positional.indexOf(n, at);
      if (found < 0) return false;
      at = found + 1;
      return true;
    });
    if (!inOrder) continue;
    if (!flags.every((f) => words.some((w) => w === f || w.startsWith(`${f}=`)))) continue;
    return spec;
  }
  return undefined;
}

const COPIERS = new Set(["cp", "mv", "install", "ln"]);

/** A copy is not a read while its destination is still guarded: a Secret File, or a directory the file keeps its name in. */
function copyStaysSecret(cmd: SimpleCommand, programIndex: number, hits: ReturnType<typeof secretTokens>, cwd: string): boolean {
  const dest = cmd.tokens.slice(programIndex + 1).filter((t) => !t.redirect && !t.text.startsWith("-")).at(-1);
  if (!dest) return false;
  if (hits.some((h) => h.token === dest)) return true;
  if (dest.text.endsWith("/")) return true;
  try {
    return statSync(resolve(cwd, dest.text)).isDirectory();
  } catch {
    return false;
  }
}

function consumes(cmd: SimpleCommand, programIndex: number, program: string, hits: ReturnType<typeof secretTokens>, policy: Policy, cwd: string): boolean {
  const words = cmd.tokens.map((t) => t.text);
  for (const spec of policy.consumers.map(parseConsumer)) {
    if (spec.program[0] !== program) continue;
    if (!spec.program.slice(1).every((p, i) => words[programIndex + 1 + i] === p)) continue;
    if (COPIERS.has(program) && !copyStaysSecret(cmd, programIndex, hits, cwd)) continue;
    if (!spec.flag) return true;
    const flag = spec.flag;
    // Every Secret File token must be that flag's value (`--env-file X` or `--env-file=X`).
    const ok = hits.every(({ token }) => {
      const at = cmd.tokens.indexOf(token);
      return token.text.startsWith(`${flag}=`) || (at > 0 && cmd.tokens[at - 1]!.text === flag);
    });
    if (ok) return true;
  }
  return false;
}

/** The command a `secrets-axi run -- <child>` chain runs, however deep; undefined for secrets-axi's own commands. */
function resolveChild(outer: SimpleCommand): { cmd: SimpleCommand; prog: { name: string; index: number } } | undefined {
  let cmd = outer;
  let prog = programOf(cmd);
  if (!prog) return undefined;
  // `keys`/`set`/`check` name the file on purpose; `run -- <child>` is judged by the child.
  let hops = 0;
  while (prog.name === "secrets-axi" && hops++ < 4) {
    const child = runChild(cmd, prog.index);
    const childProg = child ? programOf(child) : undefined;
    if (!child || !childProg) break;
    cmd = child;
    prog = childProg;
  }
  return prog.name === "secrets-axi" ? undefined : { cmd, prog };
}

/** A Secret File read (not by an Allowed Consumer) or a Secret Fetch, or undefined. */
function judge(
  outer: SimpleCommand,
  policy: Policy,
  cwd: string,
  home: string | undefined,
  depth = 0,
): { hits: ReturnType<typeof secretTokens> } | { fetch: string } | undefined {
  const resolved = resolveChild(outer);
  if (!resolved) return undefined;
  const { cmd, prog } = resolved;
  // `bash -c '<line>'` (also `-lc`, under sudo): the line is judged command by command.
  const code = SHELLS.has(prog.name) ? shellCode(cmd, prog.index) : undefined;
  if (code !== undefined) {
    if (depth > 4) return undefined;
    for (const inner of parseCommand(code)) {
      const verdict = judge(inner, policy, cwd, home, depth + 1);
      if (verdict) return verdict;
    }
    return undefined;
  }
  const hits = secretTokens(cmd, policy, cwd, home, prog.name);
  if (hits.length > 0) return consumes(cmd, prog.index, prog.name, hits, policy, cwd) ? undefined : { hits };
  const fetch = isFetch(cmd, prog.index, policy);
  return fetch ? { fetch } : undefined;
}

const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "fish"]);

/** The code of `bash -c <code>` / `bash -lc <code>`, or undefined. */
function shellCode(cmd: SimpleCommand, programIndex: number): string | undefined {
  const words = cmd.tokens.map((t) => t.text);
  const at = words.findIndex((w, i) => i > programIndex && /^-[A-Za-z]*c[A-Za-z]*$/.test(w));
  return at > 0 ? words[at + 1] : undefined;
}

/** ssh options that take a value (`-o X`, `-p 22`, ...). */
const SSH_VALUED = new Set(["-o", "-p", "-i", "-l", "-F", "-J", "-L", "-R", "-D", "-b", "-c", "-E", "-e", "-I", "-m", "-O", "-Q", "-S", "-W", "-w", "-B"]);

/** Host and remote line of `ssh [opts] host <words...>`; ssh joins the words with spaces for the remote shell. */
function sshRemote(cmd: SimpleCommand, programIndex: number): { host: string; line: string } | undefined {
  const words = cmd.tokens.filter((t) => !t.redirect).map((t) => t.text);
  let i = programIndex + 1;
  while (i < words.length && words[i]!.startsWith("-")) i += SSH_VALUED.has(words[i]!) ? 2 : 1;
  const host = words[i];
  const rest = words.slice(i + 1);
  return host && rest.length > 0 ? { host, line: rest.join(" ") } : undefined;
}

function bash(call: ToolCall, policy: Policy, home: string | undefined): Decision {
  const command = typeof call.input["command"] === "string" ? call.input["command"] : "";
  if (command.trim() === "") return { kind: "pass" };
  const commands = parseCommand(command);
  const cwd = call.cwd;
  const readers: SimpleCommand[] = [];
  // Dotenv-shaped Secret Files the command read or sourced: the suggested `run` must load them.
  const envReads: string[] = [];
  let denial: Decision | undefined;
  // Set when the denied read is on an ssh remote: the Hint cannot load that file locally.
  let denialHost: string | undefined;
  const rewrites: Array<{ at: number; insert: string }> = [];

  for (const outer of commands) {
    const outerProg = programOf(outer);
    // `ssh host '<line>'`: the remote shell runs the line; each of its commands is judged, by name only.
    const remote = outerProg?.name === "ssh" ? sshRemote(outer, outerProg.index) : undefined;
    if (remote) {
      for (const inner of parseCommand(remote.line)) {
        const verdict = judge(inner, policy, cwd, home);
        if (!verdict) continue;
        readers.push(outer);
        if (!denial) {
          if ("hits" in verdict) denialHost = remote.host;
          denial =
            "hits" in verdict
              ? { kind: "deny", rule: `secretFiles:${verdict.hits[0]!.pattern}`, file: verdict.hits[0]!.path, hint: "" }
              : { kind: "deny", rule: `fetchCommands:${verdict.fetch}`, hint: "" };
        }
      }
      continue;
    }
    const resolved = resolveChild(outer);
    if (!resolved) continue;
    const { cmd, prog } = resolved;
    const verdict = judge(cmd, policy, cwd, home);
    if (verdict && "hits" in verdict) {
      const hits = verdict.hits;
      readers.push(outer);
      for (const hit of hits) {
        const shown = display(hit.path, cwd, home);
        if (ENV_SHAPED.test(basename(hit.path)) && !envReads.includes(shown)) envReads.push(shown);
      }
      if (!denial) {
        const file = display(hits[0]!.path, cwd, home);
        denial = { kind: "deny", rule: `secretFiles:${hits[0]!.pattern}`, file, hint: "" };
      }
      continue;
    }
    if (verdict) {
      readers.push(outer);
      if (!denial) denial = { kind: "deny", rule: `fetchCommands:${verdict.fetch}`, hint: "" };
      continue;
    }
    const search = RECURSIVE_SEARCH[prog.name];
    if (search) {
      const words = cmd.tokens.slice(prog.index + 1).map((t) => t.text);
      const recursive = search.always || words.some((w) => search.flags.some((f) => w === f || w.startsWith(`${f}=`))) || words.some((w) => /^-[a-zA-Z]*[rR]/.test(w) && !w.startsWith("--"));
      const alreadyExcluded = words.some((w, i) => {
        const value = exclusionValue(w, words[i - 1]);
        return value !== undefined && excludesSecrets(value, policy);
      });
      if (recursive && !alreadyExcluded) {
        rewrites.push({ at: cmd.tokens[prog.index]!.end, insert: ` ${search.exclude(basenamePatterns(policy))}` });
      }
    }
  }

  if (denial && denial.kind === "deny") {
    const run = `secrets-axi run ${envFileFlags(envReads, policy)}-- ${runTarget(command, commands, readers)}`;
    if (denial.rule.startsWith("fetchCommands:")) {
      const spec = denial.rule.slice("fetchCommands:".length);
      const aws = spec.startsWith("aws ");
      const keychain = spec === "security find-generic-password" ? keychainSpec(readers[0]!, command) : undefined;
      const form = aws
        ? `secrets-axi run --aws-secret ${fetchId(readers[0]!) ?? "<id>"} -- <command>`
        : keychain
          ? `secrets-axi run --keychain ${keychain} -- <command>`
          : run;
      denial.hint = `\`${spec}\` prints a secret value into the transcript. Run \`${form}\` to inject it into a command's environment instead${aws ? "; `aws secretsmanager list-secrets` / `describe-secret` are fine for names" : ""}`;
    } else if (denialHost) {
      denial.hint = `${denialHost}:${denial.file} is a Secret File on a remote host - reading it puts its values in the transcript. Run \`ssh ${denialHost} npx -y secrets-axi keys ${quote(denial.file!)}\` (needs Node there) for variable names and shapes`;
    } else {
      const file = denial.file!;
      denial.hint = `${file} is a Secret File - reading it puts its values in the transcript. Run \`${run}\` to run with it loaded, \`secrets-axi keys ${quote(file)}\` for variable names and shapes, \`secrets-axi set ${quote(file)} KEY=value\` to change one`;
    }
    return denial;
  }

  if (rewrites.length > 0) {
    let rewritten = command;
    for (const r of rewrites.sort((a, b) => b.at - a.at)) rewritten = `${rewritten.slice(0, r.at)}${r.insert}${rewritten.slice(r.at)}`;
    return { kind: "rewrite", rule: "recursiveSearch", input: { ...call.input, command: rewritten }, note: "Secret Files excluded from the recursive search" };
  }
  return { kind: "pass" };
}

/**
 * What the Hint puts after `run --`: the agent's line without its reads and `set -a`/`set +a`, operators kept.
 * The Runner spawns without a shell, so anything but one plain command becomes `sh -c '...'`. A read that does not
 * stand alone in a `;`/`&&` list (piped, in a subshell, group, loop or substitution) gets the `<command>` placeholder.
 */
function runTarget(command: string, commands: SimpleCommand[], readers: SimpleCommand[]): string {
  const inside = (a: SimpleCommand, b: SimpleCommand): boolean => a !== b && a.start >= b.start && a.end <= b.end;
  const top = commands.filter((c) => !commands.some((o) => inside(c, o))).sort((a, b) => a.start - b.start);
  if (readers.some((r) => !top.includes(r))) return "<command>";
  if (top.some((c) => SHELL_KEYWORDS.has(c.tokens[0]?.text ?? ""))) return "<command>";
  const seps = top.map((c, i) => (i === 0 ? "" : command.slice(top[i - 1]!.end, c.start).trim()));
  // Subshells, groups and heredoc bodies show up between commands; only plain operators may join them.
  if (seps.some((s) => !JOINS.has(s))) return "<command>";
  const cut = top.map((c) => readers.includes(c) || isAllexport(c));
  const listSep = (s: string | undefined): boolean => s === undefined || s === "" || s === ";" || s === "&&";
  if (cut.some((x, i) => x && (!listSep(seps[i]) || !listSep(seps[i + 1])))) return "<command>";
  const keep = top
    .map((c, i) => ({ c, sep: seps[i] || ";", text: command.slice(c.start, c.end).trim() }))
    .filter(({ text }, i) => !cut[i] && text !== "");
  if (!keep.some(({ c }) => programOf(c) && !SETUP_ONLY.has(programOf(c)!.name))) return "<command>";
  const only = keep.length === 1 ? keep[0]! : undefined;
  if (only && programOf(only.c)!.index === 0) return only.text;
  return `sh -c ${quote(keep.map(({ sep, text }, i) => (i === 0 ? text : `${sep === ";" ? ";" : ` ${sep}`} ${text}`)).join(""))}`;
}

const JOINS = new Set(["", ";", "&&", "||", "|", "|&"]);

/** `set -a` / `set +a` / `set -o allexport`: the wrapper around a `source`, meaningless under the Runner. */
function isAllexport(cmd: SimpleCommand): boolean {
  const words = cmd.tokens.filter((t) => !t.redirect).map((t) => t.text);
  return words[0] === "set" && words.length > 1 && words.slice(1).every((w) => /^[-+]a$/.test(w) || /^[-+]o$/.test(w) || w === "allexport");
}

const SHELL_KEYWORDS = new Set(["for", "while", "until", "if", "then", "elif", "else", "fi", "do", "done", "case", "esac", "select", "function", "!"]);

const SETUP_ONLY = new Set(["cd", "pushd", "popd", "set", "export", "unset", "shopt", "ulimit", "umask", "true", ":"]);

const ENV_SHAPED = /^\.(env|secrets|envrc)(\..+)?$|\.env$/;

/**
 * `--env-file` flags so the suggested run loads exactly what the command read (they replace the Policy's envFiles).
 * Empty when the command read exactly the defaults.
 */
function envFileFlags(reads: string[], policy: Policy): string {
  if (reads.length === 0 || (reads.length === policy.envFiles.length && reads.every((f, i) => policy.envFiles[i] === f))) return "";
  return reads.map((f) => `--env-file ${quote(f)} `).join("");
}

function fetchId(cmd: SimpleCommand): string | undefined {
  const words = cmd.tokens.map((t) => t.text);
  for (const flag of ["--secret-id", "--name", "--names"]) {
    const eq = words.find((w) => w.startsWith(`${flag}=`));
    if (eq) return eq.slice(flag.length + 1);
    const at = words.indexOf(flag);
    if (at >= 0 && words[at + 1]) return words[at + 1];
  }
  return undefined;
}

/** `<service>/<account>=NAME` for a `security find-generic-password -s S -a A`; NAME from `NAME="$(security ...)"`. */
function keychainSpec(cmd: SimpleCommand, command: string): string | undefined {
  const words = cmd.tokens.map((t) => t.text);
  const value = (flag: string): string | undefined => {
    const at = words.indexOf(flag);
    return at >= 0 ? words[at + 1] : undefined;
  };
  const service = value("-s");
  const account = value("-a");
  if (!service || !account) return undefined;
  const name = command.slice(0, cmd.start).match(/([A-Za-z_][A-Za-z0-9_]*)=["']?\$\(\s*$/)?.[1] ?? "<NAME>";
  return `${quote(`${service}/${account}`)}=${name}`;
}

/** For the home view and tests: the basename a Hint would show. */
export function hintName(path: string): string {
  return basename(path);
}
