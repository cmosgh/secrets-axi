// Shell-ish tokenizer for the Guard. Deterministic and bounded: quotes, backslashes, operators,
// redirections and `$(...)`/backtick substitutions. Not a shell; see PLAN.md "Known limits".

export interface Token {
  text: string;
  /** Offset of the token's first character in the original command. */
  start: number;
  end: number;
  /** Target of a redirection (`< .env`, `>> out`). */
  redirect?: boolean;
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
  let i = 0;

  const flush = (): void => {
    if (curStart < 0) return;
    tokens.push({ text: cur, start: base + curStart, end: base + i, ...(redirectNext ? { redirect: true } : {}) });
    redirectNext = false;
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
      continue;
    }
    const redirect = text.slice(i).match(/^(\d*)(>>|>&|<&|>\||<<<|<<|>|<)/);
    if (redirect && curStart < 0) {
      i += redirect[0].length;
      redirectNext = redirect[2] !== "<<" && redirect[2] !== "<<<" && !/^[<>]&/.test(redirect[2]!);
      while (text[i] === " " || text[i] === "\t") i++;
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

const WRAPPERS = new Set(["sudo", "env", "command", "exec", "time", "nohup", "nice", "builtin", "doas", "timeout", "xargs", "caffeinate", "stdbuf", "unbuffer"]);

/** The program of a simple command: skips `VAR=x` assignments and common wrappers (and their option flags). */
export function programOf(cmd: SimpleCommand): { name: string; index: number } | undefined {
  let i = 0;
  const tokens = cmd.tokens;
  while (i < tokens.length) {
    const t = tokens[i]!;
    if (t.redirect || /^[A-Za-z_][A-Za-z0-9_]*=/.test(t.text)) {
      i++;
      continue;
    }
    const name = t.text.replace(/^.*\//, "");
    if (WRAPPERS.has(name)) {
      i++;
      // `timeout 5`, `nice -n 5`, `sudo -u x`: skip the wrapper's own arguments.
      while (i < tokens.length && (tokens[i]!.text.startsWith("-") || (name === "timeout" && /^\d/.test(tokens[i]!.text)))) i++;
      if (name === "sudo" || name === "doas" || name === "nice") {
        while (i < tokens.length && !tokens[i]!.text.startsWith("-") && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[i]!.text)) i++;
      }
      continue;
    }
    return { name, index: i };
  }
  return undefined;
}
