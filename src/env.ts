// dotenv-format parser and in-place editor. Never logs values.
import { readFileSync, writeFileSync } from "node:fs";

export interface EnvEntry {
  key: string;
  value: string;
  /** 1-based line of the assignment. */
  line: number;
}

const ASSIGN = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/;

/** Parse dotenv text: `KEY=value`, `export KEY=value`, quotes, `#` comments, multi-line double-quoted values. Last assignment wins. */
export function parseEnv(text: string): EnvEntry[] {
  const lines = text.split(/\r?\n/);
  const entries: EnvEntry[] = [];
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i]!.match(ASSIGN);
    if (!m) continue;
    const key = m[1]!;
    let raw = m[2]!;
    let value: string;
    const line = i + 1;
    if (raw.startsWith('"')) {
      let body = raw.slice(1);
      let closed = closingQuote(body, '"');
      while (closed < 0 && i + 1 < lines.length) {
        body += `\n${lines[++i]!}`;
        closed = closingQuote(body, '"');
      }
      value = (closed < 0 ? body : body.slice(0, closed)).replace(/\\n/g, "\n").replace(/\\r/g, "\r").replace(/\\t/g, "\t").replace(/\\(["\\$])/g, "$1");
    } else if (raw.startsWith("'")) {
      const body = raw.slice(1);
      const closed = body.indexOf("'");
      value = closed < 0 ? body : body.slice(0, closed);
    } else {
      const hash = raw.search(/\s#/);
      if (hash >= 0) raw = raw.slice(0, hash);
      value = raw.trim();
    }
    const existing = entries.findIndex((e) => e.key === key);
    if (existing >= 0) entries.splice(existing, 1);
    entries.push({ key, value, line });
  }
  return entries;
}

function closingQuote(body: string, quote: string): number {
  for (let i = 0; i < body.length; i++) {
    if (body[i] === "\\") i++;
    else if (body[i] === quote) return i;
  }
  return -1;
}

export function envMap(entries: readonly EnvEntry[]): Map<string, string> {
  return new Map(entries.map((e) => [e.key, e.value]));
}

/** Shape of a value: length and character class, never the value. */
export function shapeOf(value: string): string {
  if (value === "") return "empty";
  const n = value.length;
  if (/^\d+$/.test(value)) return `len ${n} digits`;
  if (/^(true|false|yes|no|on|off)$/i.test(value)) return "boolean";
  if (/^[0-9a-f]+$/i.test(value) && n >= 8) return `len ${n} hex`;
  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(value) && n > 30) return `len ${n} jwt`;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) return `len ${n} url${/\/\/[^/@]+:[^/@]+@/.test(value) ? " with credentials" : ""}`;
  if (/^[A-Za-z0-9+/]+=*$/.test(value) && n % 4 === 0 && n >= 16) return `len ${n} base64`;
  if (/^-----BEGIN /.test(value)) return "pem block";
  if (/^[A-Za-z0-9_-]+$/.test(value)) return `len ${n} alnum`;
  if (value.includes("\n")) return `len ${n} multiline`;
  return `len ${n} text`;
}

export interface SetResult {
  key: string;
  action: "set" | "replaced" | "removed" | "absent";
  line: number;
}

function quoteValue(value: string): string {
  if (/^[A-Za-z0-9_./:@+-]*$/.test(value)) return value;
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n").replace(/\$/g, "\\$")}"`;
}

/** Replace the last assignment of `key` in place, or append one; every other byte stays. */
export function setKey(path: string, key: string, value: string): SetResult {
  const text = readFileSync(path, "utf8");
  const lines = text.split("\n");
  let target = -1;
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i]!.match(ASSIGN);
    if (m && m[1] === key) target = i;
  }
  const assignment = `${key}=${quoteValue(value)}`;
  if (target >= 0) {
    const prefix = lines[target]!.match(/^\s*(export\s+)?/)![0];
    lines[target] = `${prefix}${assignment}`;
    writeFileSync(path, lines.join("\n"));
    return { key, action: "replaced", line: target + 1 };
  }
  const trailing = text.endsWith("\n") || text === "";
  writeFileSync(path, `${text}${trailing ? "" : "\n"}${assignment}\n`);
  return { key, action: "set", line: lines.length + (trailing ? 0 : 1) };
}

/** Remove every assignment line of `key`. */
export function unsetKey(path: string, key: string): SetResult {
  const text = readFileSync(path, "utf8");
  const lines = text.split("\n");
  let first = -1;
  const kept = lines.filter((line, i) => {
    const m = line.match(ASSIGN);
    if (m && m[1] === key) {
      if (first < 0) first = i;
      return false;
    }
    return true;
  });
  if (first < 0) return { key, action: "absent", line: 0 };
  writeFileSync(path, kept.join("\n"));
  return { key, action: "removed", line: first + 1 };
}
