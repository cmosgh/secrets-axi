# secrets-axi - plan

AXI-compliant CLI that keeps secret values out of agent transcripts. Vocabulary in `GLOSSARY.md`, decisions in `docs/adr/`.

## Goal

An agent (Claude Code, Codex, later OpenCode) can run anything that needs secrets, learn which secrets exist, and add or change one, without a secret value ever appearing in its tool output. Misuse of credentials the agent legitimately holds is out of scope: that is credential hygiene, not a reader guard.

## Two faces

### Guard (hook)

Runs on every `PreToolUse` (`Read`, `Edit`, `Write`, `Grep`, `Glob`, `Bash`) and decides from the literal call:

| Call | Decision |
|---|---|
| `Read`/`Edit`/`Write` with `file_path` a Secret File | deny; Hint `secrets-axi keys <file>` / `secrets-axi set <file> KEY=value` |
| `Grep` with `path` a Secret File | deny; Hint `secrets-axi keys <file>` |
| `Grep` over a directory | rewrite: add Secret File patterns to `glob` exclusions |
| `Bash` with a token resolving to a Secret File | deny unless the program is an Allowed Consumer; Hint `secrets-axi run -- <command>` or `keys`/`set` |
| `Bash` `grep -r`/`rg`/`ag` without an explicit Secret File | rewrite: append `--exclude` / `-g '!…'` per pattern |
| `Bash` matching a Secret Fetch | deny; Hint `secrets-axi run --aws-secret <id> -- <command>` (or the source's run form) |
| `Bash` `git show <rev>:<secret file>` | deny; other git commands pass (committed Secret Files are a session-start warning) |

Rules:
- Deterministic and listable: `secrets-axi policy` prints every list; `secrets-axi check '<command>'` prints the decision the Guard would make and why.
- Always `deny`, never `ask`: `ask` differs between agents and "approve once" is how values end up in transcripts.
- Hook entry is a bundled single file with `node:` builtins only; budget < 30 ms per call, pinned by a test.
- Hard layer: `setup hooks` also writes `Read(<pattern>)` deny rules for the built-in Secret File list into the agent's settings and removes exactly those on `uninstall`. Sandbox `denyRead` is recommended in `setup status`, never written.
- Hooks are installed per agent by secrets-axi itself (own entries only), `axi-sdk-js` has no `PreToolUse` support yet; upstream once the shape is proven. SessionStart home view goes through the SDK like ts-axi.

### Runner (CLI)

| Command | Does |
|---|---|
| `secrets-axi` | home view: Guard status, Secret Files in the repo (name, key count), detected Secret Source, other env files not loaded, `.env` tracked by git warning, the one `run` form to use |
| `run [--env-file F]... [--aws-secret ID[=NAME]]... -- <cmd>` | Guarded Run |
| `keys <file>` | Key listing (name, set/empty, shape; values for Reveal Keys) |
| `set <file> KEY=value`, `unset <file> KEY` | edit in place; prints the key name and `set`/`replaced`/`removed`, never other lines |
| `check '<command>'` / `check --read <path>` | dry run of the Guard |
| `policy` | effective Policy with the layer each entry comes from |
| `setup hooks\|status\|uninstall [--project]` | hook and deny-rule management |

Secret Source detection order, first match wins, `--source` overrides:
1. `.env` content made of `op://` refs → `op inject` (0.x: detection stub, "not supported yet")
2. `doppler.yaml` / `.infisical.json` → that tool's export (stub)
3. `.env.keys` present → `dotenvx get --all` (stub)
4. plain `.env` → own parser (v1)
5. AWS entries from Policy or `--aws-secret` → AWS SDK, merged over the env file (v1); JSON object → top-level keys as variables; bare string needs `ID=NAME`

Sources resolve; the Runner spawns the child with the merged env and masks stdout/stderr. Env files: `.env` only by default; `--env-file` repeatable in order; Policy `envFiles`. Never the `NODE_ENV` cascade.

## Policy

Built-in → `~/.config/secrets-axi/policy.json` → `.secrets-axi.json` in the repository root (optional, never required, never written by the tool). Keys: `secretFiles`, `fetchCommands`, `consumers`, `reveal`, `envFiles`, `aws`. A repository layer may only add; `remove` entries are honoured from the user layer only.

## Output

AXI conventions as in ts-axi: TOON blocks, `help[]` lines with real values, `--json`, 3-4 default fields, `test/token-budget.json` pinned. A deny Hint is at most two lines.

## Versions

- **0.1**: Guard for Claude Code and Codex (same contract), hard-layer deny rules, `run` with plain `.env` + AWS, `keys`, `set`/`unset`, `check`, `policy`, home view, source detection stubs.
- **0.2**: OpenCode plugin (`tool.execute.before`), `op`, `doppler`, `dotenvx`, `infisical` resolvers as there are repos to test against.
- Deferred: content sniffing for unnamed Secret Files, masking of encoded values (base64/URL-encoded), Windows.

## Known limits (stated in the home view)

- The Guard sees the literal command: `python -c "open('.env')"` or `$(printf '.e''nv')` pass it. The hard layer and the sandbox are the boundary for those.
- A Secret File tracked by git leaks through `git diff`/`git log -p`; secrets-axi warns, it cannot cover it.
- A child of a Guarded Run can read the Secret File itself; Masking still covers what it prints.
