// Shell-ish tokenizer for the Guard. Deterministic and bounded: quotes, backslashes, operators,
// redirections and `$(...)`/backtick substitutions. Not a shell; see PLAN.md "Known limits".

export interface Token {
  text: string;
  /** Offset of the token's first character in the original command. */
  start: number;
  end: number;
  /** Target of a redirection (`< .env`, `>> out`). */
  redirect?: boolean;
  /** Target of an output redirection (`> f`, `>> f`, `>| f`): written, not read. */
  output?: boolean;
  /** Body of a heredoc fed to an interpreter (`python3 - <<EOF`): code, scanned for string literals like `-c` code. */
  heredoc?: boolean;
}

export interface SimpleCommand {
  tokens: Token[];
  /** Offset range of the whole simple command in the original text. */
  start: number;
  end: number;
}

const OPERATORS = ["&&", "||", ";;", "|&", ";", "|", "&", "\n"];

/** Split a command line into simple commands (also those inside `$(...)` and backticks), each tokenized. */
export function parseCommand(text: string): SimpleCommand[] {
  const out: SimpleCommand[] = [];
  split(text, 0, out, 0);
  return out;
}

function split(text: string, base: number, out: SimpleCommand[], depth: number): void {
  if (depth > 4) return;
  let tokens: Token[] = [];
  let cmdStart = 0;
  let cur = "";
  let curStart = -1;
  let redirectNext = false;
  let redirectOut = false;
  // Heredoc delimiters seen on the current line; their bodies start after the next newline and are data, not commands.
  const heredocs: Array<{ delimiter: string; stripTabs: boolean; quoted: boolean }> = [];
  let i = 0;

  const flush = (): void => {
    if (curStart < 0) return;
    tokens.push({ text: cur, start: base + curStart, end: base + i, ...(redirectNext ? { redirect: true, ...(redirectOut ? { output: true } : {}) } : {}) });
    redirectNext = false;
    redirectOut = false;
    cur = "";
    curStart = -1;
  };
  const endCommand = (at: number): void => {
    flush();
    if (tokens.length > 0) out.push({ tokens, start: base + cmdStart, end: base + at });
    tokens = [];
    cmdStart = at;
  };
  const begin = (): void => {
    if (curStart < 0) curStart = i;
  };

  while (i < text.length) {
    const c = text[i]!;
    const two = text.slice(i, i + 2);
    if (c === "'") {
      begin();
      const close = text.indexOf("'", i + 1);
      const endQ = close < 0 ? text.length : close;
      cur += text.slice(i + 1, endQ);
      i = endQ + 1;
      continue;
    }
    if (c === '"') {
      begin();
      i++;
      while (i < text.length && text[i] !== '"') {
        if (text[i] === "\\" && i + 1 < text.length) {
          cur += text[i + 1];
          i += 2;
        } else if (two_at(text, i) === "$(") {
          const close = matching(text, i + 1);
          split(text.slice(i + 2, close), base + i + 2, out, depth + 1);
          cur += text.slice(i, close + 1);
          i = close + 1;
        } else if (text[i] === "`") {
          // Backticks run inside double quotes too: `echo "x `cat .env` y"`.
          const close = text.indexOf("`", i + 1);
          const endQ = close < 0 ? text.length : close;
          split(text.slice(i + 1, endQ), base + i + 1, out, depth + 1);
          cur += text.slice(i, endQ + 1);
          i = endQ + 1;
        } else {
          cur += text[i];
          i++;
        }
      }
      i++;
      continue;
    }
    if (c === "\\" && i + 1 < text.length) {
      begin();
      cur += text[i + 1];
      i += 2;
      continue;
    }
    if (two === "$(") {
      begin();
      const close = matching(text, i + 1);
      split(text.slice(i + 2, close), base + i + 2, out, depth + 1);
      cur += text.slice(i, close + 1);
      i = close + 1;
      continue;
    }
    if (c === "`") {
      begin();
      const close = text.indexOf("`", i + 1);
      const endQ = close < 0 ? text.length : close;
      split(text.slice(i + 1, endQ), base + i + 1, out, depth + 1);
      cur += text.slice(i, endQ + 1);
      i = endQ + 1;
      continue;
    }
    if (c === "(" || c === ")" || c === "{" || c === "}") {
      // Subshell and group delimiters: a boundary, not a token.
      if (curStart >= 0 && cur !== "") flush();
      else curStart = -1;
      i++;
      cmdStart = tokens.length === 0 ? i : cmdStart;
      continue;
    }
    const op = OPERATORS.find((o) => text.startsWith(o, i));
    if (op) {
      endCommand(i);
      i += op.length;
      cmdStart = i;
      if (op === "\n" && heredocs.length > 0) {
        const fed = out[out.length - 1];
        i = readHeredocBodies(text, i, heredocs.splice(0), (body, at, quoted) => heredocBody(body, base + at, quoted, fed, out, depth));
        cmdStart = i;
      }
      continue;
    }
    const redirect = text.slice(i).match(/^(\d*)(>>|>&|<&|>\||<<<|<<-|<<|>|<)/);
    if (redirect && curStart < 0) {
      i += redirect[0].length;
      while (text[i] === " " || text[i] === "\t") i++;
      const kind = redirect[2]!;
      if (kind === "<<" || kind === "<<-") {
        const word = text.slice(i).match(/^(?:'([^']*)'|"([^"]*)"|\\?([^\s;|&()<>]+))/);
        if (word) {
          heredocs.push({ delimiter: word[1] ?? word[2] ?? word[3]!, stripTabs: kind === "<<-", quoted: word[3] === undefined || word[0].startsWith("\\") });
          i += word[0].length;
        }
        continue;
      }
      redirectNext = kind !== "<<<" && !/^[<>]&/.test(kind);
      redirectOut = kind.startsWith(">");
      continue;
    }
    if (c === " " || c === "\t" || c === "\r") {
      flush();
      i++;
      continue;
    }
    begin();
    cur += c;
    i++;
  }
  endCommand(text.length);
}

/** Index just past the terminator lines of the given heredocs, in order; an unterminated body runs to the end. Each body is handed to `onBody`. */
function readHeredocBodies(
  text: string,
  from: number,
  docs: Array<{ delimiter: string; stripTabs: boolean; quoted: boolean }>,
  onBody: (body: string, at: number, quoted: boolean) => void,
): number {
  let i = from;
  for (const doc of docs) {
    const start = i;
    let end = text.length;
    for (;;) {
      if (i >= text.length) break;
      const nl = text.indexOf("\n", i);
      const line = text.slice(i, nl < 0 ? text.length : nl);
      end = i;
      i = nl < 0 ? text.length : nl + 1;
      if ((doc.stripTabs ? line.replace(/^\t+/, "") : line) === doc.delimiter) break;
      end = i;
    }
    onBody(text.slice(start, end), start, doc.quoted);
  }
  return i;
}

const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "fish"]);
const INTERPRETERS = new Set(["python", "python3", "python2", "node", "bun", "deno", "ruby", "perl", "php", "osascript"]);

/**
 * A heredoc body is data, except where bash runs it: a shell reads it as commands, an interpreter as code
 * (string literals are path candidates), and an unquoted delimiter expands `$(...)` and backticks inside it.
 */
function heredocBody(body: string, at: number, quoted: boolean, fed: SimpleCommand | undefined, out: SimpleCommand[], depth: number): void {
  const prog = fed ? programOf(fed) : undefined;
  if (prog && SHELLS.has(prog.name)) {
    split(body, at, out, depth + 1);
    return;
  }
  if (!quoted) {
    // `\`` and `\$(` are literal in a heredoc body; the alternation consumes `\x` pairs so they never open a substitution.
    for (const m of body.matchAll(/\\[\s\S]|\$\(([^()]*)\)|`((?:[^`\\]|\\[\s\S])*)`/g)) {
      if (m[1] === undefined && m[2] === undefined) continue;
      split(m[1] ?? m[2]!, at + m.index + (m[1] !== undefined ? 2 : 1), out, depth + 1);
    }
  }
  if (prog && fed && INTERPRETERS.has(prog.name)) fed.tokens.push({ text: body, start: at, end: at + body.length, heredoc: true });
}

function two_at(text: string, i: number): string {
  return text.slice(i, i + 2);
}

/** Index of the `)` matching the `(` at `open`, or the text end. */
function matching(text: string, open: number): number {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    const c = text[i];
    if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth === 0) return i;
    } else if (c === "'" || c === '"') {
      const close = text.indexOf(c, i + 1);
      if (close < 0) return text.length;
      i = close;
    }
  }
  return text.length;
}

/** Wrappers the Guard looks through, with the options of each that take a value. */
const WRAPPERS: Record<string, string[]> = {
  sudo: ["-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U", "-T"],
  doas: ["-u", "-C"],
  env: ["-u", "-C", "-S", "--unset", "--chdir", "--split-string"],
  command: [],
  exec: ["-a"],
  time: ["-f", "-o"],
  nohup: [],
  nice: ["-n", "--adjustment"],
  builtin: [],
  timeout: ["-s", "-k", "--signal", "--kill-after"],
  xargs: ["-I", "-n", "-P", "-d", "-L", "-s", "-E", "-a"],
  caffeinate: ["-t", "-w"],
  stdbuf: ["-i", "-o", "-e"],
  unbuffer: [],
  nix: ["--option"],
  npx: ["-p", "--package", "-c", "--call"],
  bunx: ["-p", "--package"],
};

/** The program of a simple command: skips `VAR=x` assignments and common wrappers with their options. */
/** Shell keywords that start a segment before the command they introduce (`do cat .env`, `then node x`). */
const KEYWORDS = new Set(["do", "then", "else", "elif", "if", "while", "until", "!", "{"]);

export function programOf(cmd: SimpleCommand): { name: string; index: number } | undefined {
  let i = 0;
  const tokens = cmd.tokens;
  while (i < tokens.length) {
    const t = tokens[i]!;
    if (t.redirect || /^[A-Za-z_][A-Za-z0-9_]*=/.test(t.text) || KEYWORDS.has(t.text)) {
      i++;
      continue;
    }
    const name = t.text.replace(/^.*\//, "");
    const valued = WRAPPERS[name];
    if (valued) {
      i++;
      while (i < tokens.length) {
        const w = tokens[i]!.text;
        if (name === "timeout" && /^\d+[smhd]?$/.test(w)) {
          i++;
          continue;
        }
        if (!w.startsWith("-")) break;
        i += valued.includes(w) && !w.includes("=") ? 2 : 1;
      }
      continue;
    }
    return { name, index: i };
  }
  return undefined;
}
