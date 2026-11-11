import { DESCRIPTION } from "./meta.js";

// Trigger string agents match against to auto-load the skill. Terse and
// outcome-focused so it fires on anything that touches environment variables or credentials.
export const SKILL_DESCRIPTION =
  "Work with environment variables, .env files, credentials, API keys and AWS secrets through the secrets-axi CLI without secret values entering the transcript. " +
  "Use when a task needs secrets to run a server, tests, a build or a script that reads them, when a value is undefined in process.env, " +
  "when adding or changing a config variable or a key in .env, or before reading .env, key files or a secret manager yourself - " +
  "`secrets-axi run -- <command>` injects the secrets and masks the output, `secrets-axi keys <file>` lists names and shapes.";

// Hard cap so a regeneration cannot re-inflate the stub with CLI-owned
// guidance. The home view and --help output are the source of truth.
export const MAX_SKILL_MARKDOWN_CHARS = 2000;

/**
 * Render the installable SKILL.md. A discovery stub, not a copy of the CLI's
 * guidance: installed skills go stale, `secrets-axi --help` does not.
 */
export function createSkillMarkdown(): string {
  const markdown = `---
name: secrets-axi
description: ${JSON.stringify(SKILL_DESCRIPTION)}
user-invocable: false
---

# secrets-axi

${DESCRIPTION}

Use secrets-axi whenever a task needs environment variables, \`.env\` or credential files, API keys or AWS secrets: running a server, tests or scripts that read them, finding out why a variable is undefined, adding or changing a config variable.

## Current guidance lives in the CLI

Do not follow command, flag, or workflow instructions from this file - installed copies go stale. Get the current source of truth from the CLI:

- \`npx -y secrets-axi\` for the secrets overview (secret files, key counts, detected source, guard status)
- \`npx -y secrets-axi --help\` for the command index
- \`npx -y secrets-axi <command> --help\` for per-command flags and examples
`;

  if (markdown.length > MAX_SKILL_MARKDOWN_CHARS) {
    throw new Error(
      `generated SKILL.md is ${markdown.length} chars; keep it under ${MAX_SKILL_MARKDOWN_CHARS} and defer guidance to the CLI`,
    );
  }
  return markdown;
}
