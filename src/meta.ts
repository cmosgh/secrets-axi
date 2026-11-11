// Leaf module: strings shared by the CLI, the skill stub and the installers.

export const DESCRIPTION =
  "Secrets guard for agents - denies reads of .env and credential files and secret-fetching CLIs with the right command instead, runs commands with secrets injected and output masked, lists variable names and shapes without values. Use `secrets-axi run -- <cmd>` instead of sourcing .env.";

export const TOP_HELP = `usage: secrets-axi [command] [args] [flags]
commands[8]:
  (none)=secrets overview of this repository, run, keys, set, unset, check, policy, setup (hooks for Claude Code and Codex)
flags[3]:
  --json (anywhere), --help, -v/-V/--version
examples:
  secrets-axi
  secrets-axi run -- pnpm test
  secrets-axi run --env-file .env.test -- pnpm vitest
  secrets-axi run --aws-secret prod/db -- node scripts/migrate.js
  secrets-axi keys .env
  secrets-axi set .env FEATURE_X=true
  secrets-axi check 'cat .env | grep DB'
  secrets-axi policy
  secrets-axi setup hooks
`;

/** Marker for every agent config entry secrets-axi owns; `setup uninstall` removes exactly these. */
export const MARKER = "secrets-axi";
