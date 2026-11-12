import type { Writable } from "node:stream";

export interface CommandContext {
  cwd: string;
  /** Home directory for `~` patterns and the user policy (tests inject a temp dir). */
  home?: string;
  /** User policy path override (tests). */
  userPolicyPath?: string;
  /** Streams a Guarded Run writes the child's masked output to (default process.stdout/stderr). */
  io?: { stdout: Writable; stderr: Writable };
  /** Test seam for `run --keychain`: returns the password for a service/account. */
  keychain?: (spec: { service: string; account: string }) => string;
}
