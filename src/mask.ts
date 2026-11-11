// Masking: every injected value becomes `<NAME>` in a child's output. The boundary (ADR 0001).
import { Transform } from "node:stream";

/** Values shorter than this are not masked: they would shred ordinary output. */
export const MIN_MASK_LENGTH = 4;

export interface MaskEntry {
  value: string;
  replacement: string;
}

/** Longest values first, so a value that contains another is replaced whole. Names are deduplicated by value. */
export function maskTable(env: ReadonlyMap<string, string>): MaskEntry[] {
  const byValue = new Map<string, string>();
  for (const [name, value] of env) {
    if (value.length < MIN_MASK_LENGTH || byValue.has(value)) continue;
    byValue.set(value, `<${name}>`);
  }
  return [...byValue].map(([value, replacement]) => ({ value, replacement })).sort((a, b) => b.value.length - a.value.length);
}

export function maskText(text: string, table: readonly MaskEntry[]): string {
  let result = text;
  for (const { value, replacement } of table) result = result.split(value).join(replacement);
  return result;
}

/**
 * Stream transform with a carry-over so a value split across two chunks is still caught:
 * everything but the last `longest - 1` characters is flushed per chunk.
 */
export class MaskStream extends Transform {
  private carry = "";
  private readonly keep: number;

  constructor(private readonly table: readonly MaskEntry[]) {
    super({ decodeStrings: true });
    this.keep = Math.max(0, ...table.map((e) => e.value.length - 1));
  }

  override _transform(chunk: Buffer, _enc: BufferEncoding, done: (error?: Error | null, data?: unknown) => void): void {
    const text = this.carry + chunk.toString("utf8");
    const masked = maskText(text, this.table);
    // The carry is taken from the masked text: a replaced value is never re-matched, an unfinished one is retried.
    const cut = Math.max(0, masked.length - this.keep);
    const safe = masked.lastIndexOf("\n", cut) >= 0 && this.keep > 0 ? Math.max(cut, masked.lastIndexOf("\n", cut) + 1) : cut;
    this.carry = masked.slice(safe);
    done(null, masked.slice(0, safe));
  }

  override _flush(done: (error?: Error | null, data?: unknown) => void): void {
    done(null, maskText(this.carry, this.table));
    this.carry = "";
  }
}
