# secrets-axi

Agent-ergonomic **secrets guard**, built on the [AXI](https://axi.md) principles: token-efficient [TOON](https://toonformat.dev/) output, minimal schemas, definitive empty states, structured errors and next-step hints.

It keeps secret values out of agent transcripts. A **Guard** hook denies the obvious reads of `.env` and credential files (and of secret-fetching CLIs) and tells the agent the command to run instead; a **Runner** runs that command with the secrets injected and every injected value masked in its output. Misuse of credentials the agent legitimately holds is out of scope: that is credential hygiene, not a reader guard.

## Install

Requires Node.js 20+.

```sh
npm install -g secrets-axi
```

Then install the Guard hook for your agent (Claude Code and Codex share one contract):

```sh
secrets-axi setup hooks     # PreToolUse hook + Read(...) deny rules for the built-in Secret Files
secrets-axi setup status    # what is installed; recommends a sandbox denyRead (never writes it)
secrets-axi setup uninstall # removes exactly the entries secrets-axi added
```

`--project` installs for the current repository only. The hook is one bundled file with `node:` builtins only (budget: under 30 ms per call, pinned by a test). Optionally add the on-demand Agent Skill, and one line in `CLAUDE.md` / `AGENTS.md`:

```sh
npx skills add cmosgh/secrets-axi --skill secrets-axi
```

```
Use `secrets-axi run -- <command>` to run anything that needs .env or other secrets; never read or source .env yourself.
```

## Two faces

### Guard (hook)

Runs before every `Read`, `Edit`, `Write`, `Grep`, `Glob` and `Bash` call and decides from the literal call. Deterministic and listable: every decision comes from a [Policy](#policy) entry, `secrets-axi policy` prints them all, `secrets-axi check '<command>'` shows the decision the Guard would make and why.

It always **denies**, never `ask` ("approve once" is how values end up in transcripts), and never rewrites a call except one case: a directory-wide search (the Grep tool, `grep -r`, `rg`, `ag`) gets the Secret File patterns added as exclusions.

| Call | Decision |
| --- | --- |
| `Read` / `Edit` / `Write` of a Secret File | deny; Hint: `secrets-axi keys <file>` or `secrets-axi set <file> KEY=value` |
| `Grep` with `path` a Secret File | deny; Hint: `secrets-axi keys <file>` |
| `Grep` over a directory, `grep -r` / `rg` / `ag` without an explicit Secret File | rewrite: exclusions for the Secret File patterns |
| `Bash` with a token that resolves to a Secret File | deny unless the program is an Allowed Consumer (`docker --env-file`, `dotenv -e`, `dotenvx run`, `secrets-axi`, and `cp`/`mv`/`install`/`ln` to a destination that is still a Secret File or a directory); Hint: `secrets-axi run -- <command>` |
| `Bash` matching a Secret Fetch (`aws secretsmanager get-secret-value`, `op read`, `vault kv get`, ...) | deny; Hint: `secrets-axi run --aws-secret <id> -- <command>`, `--keychain <service>/<account>=NAME` for `security find-generic-password`, or the source's run form |
| `Bash` `git show <rev>:<secret file>` | deny; other git commands pass |

What the agent is told instead, for `Read` of `.env` (the hook's `permissionDecisionReason`):

```
secrets-axi: .env is a Secret File - its values must not enter the transcript. Run `secrets-axi keys .env` for its variable names and shapes, or `secrets-axi run -- <command>` to run something with it loaded
```

A Hint is at most two lines with the exact replacement command, real paths and names filled in. Listing or describing secrets (names only) is not a Secret Fetch and passes.

### Runner (CLI)

Masking is the boundary, the hook is the nudge: every injected value is replaced by `<VARIABLE_NAME>` in the child's stdout and stderr, unconditionally, with no flag to switch it off. Only Reveal Keys (`NODE_ENV`, `PORT`, `HOST`, `LOG_LEVEL`, `VITE_*`, ... - `secrets-axi policy reveal` lists them) and values shorter than four characters are left as they are: masking `development` would shred every path containing the word.

| Command | What it does |
| --- | --- |
| `secrets-axi` | Home view: Guard status, Secret Files in the repository (name, key count), detected Secret Source, other env files not loaded, a warning when `.env` is tracked by git, the one `run` form to use |
| `run [--env-file F]... [--aws-secret ID[=NAME]]... [--keychain S/A=NAME]... -- <cmd>` | Guarded Run: resolve the secrets, spawn `<cmd>` with them in its environment, mask its output |
| `keys <file>` | Key listing: each variable's name, set or empty, and the shape of its value (length, character class). Values only for Reveal Keys (`NODE_ENV`, `PORT`, `VITE_*`, ...) |
| `set <file> KEY=value`, `unset <file> KEY` | Edit in place; prints the key name and `set` / `replaced` / `removed`, never any other line |
| `check '<command>'`, `check --read <path>` | Dry run of the Guard: the decision and the Policy entry behind it |
| `policy` | Effective Policy with the layer each entry comes from |
| `setup hooks\|status\|uninstall [--project]` | Hook and deny-rule management |

`secrets-axi <command> --help` prints the flag reference; `--json` prints the decoded payload anywhere.

```sh
secrets-axi run -- pnpm test
secrets-axi run --env-file .env.test -- pnpm vitest
secrets-axi run --aws-secret prod/db -- node scripts/migrate.js
secrets-axi run --keychain mysql-axi/develop=DB_PASSWORD -- npm run cli
secrets-axi keys .env
secrets-axi set .env FEATURE_X=true
secrets-axi check 'cat .env | grep DB'
```

#### Secret Sources

The first match wins; `--source` overrides. A source only resolves values: the Runner merges them, spawns the child once and masks its output, so every source gets the same guarantee.

1. `.env` made of `op://` references: `op inject` (detected, not supported yet)
2. `doppler.yaml` / `.infisical.json`: that tool's export (detected, not supported yet)
3. `.env.keys` present: `dotenvx get --all` (detected, not supported yet)
4. plain `.env`: built-in parser
5. AWS Secrets Manager / SSM entries from the Policy or `--aws-secret`: AWS SDK, merged over the env file (a JSON object becomes one variable per top-level key; a bare string needs `ID=NAME`)
6. macOS keychain generic passwords from `--keychain <service>/<account>=NAME`, through the `security` CLI (macOS asks the user the first time for items another app created)

Only `.env` is loaded by default; `--env-file` is repeatable and ordered, and the Policy `envFiles` key sets the default. The `NODE_ENV` cascade (`.env.local`, `.env.production`, ...) is never applied.

## Policy

Three layers, merged in order: built-in, then `~/.config/secrets-axi/policy.json`, then `.secrets-axi.json` in the repository root. The repository file is optional, never required and never written by the tool. A repository layer may only add (and add Reveal Keys); `remove` entries are honoured from the user layer only, so a cloned repo can never switch the Guard off. `secrets-axi policy` shows each entry with its layer.

| Key | What it lists |
| --- | --- |
| `secretFiles` | Secret File patterns by name (`.env`, `.env.*`, `*.pem`, `id_*`, `~/.aws/credentials`, `~/.npmrc`, ...), never by content; `.env.example`, `.env.sample`, `.env.template` and `*.pub` are exceptions |
| `fetchCommands` | Secret Fetch command prefixes (`aws ssm get-parameter --with-decryption`, `op read`, `vault kv get`, `doppler secrets`, ...) |
| `consumers` | Allowed Consumers: programs that load a Secret File without printing it |
| `reveal` | Reveal Keys: variables whose value a key listing may show |
| `envFiles` | Env files a Guarded Run loads, in order (default `.env`) |
| `aws` | AWS Secrets Manager ids (`prod/db`) or `id=NAME` for string secrets |

```json
{
  "secretFiles": ["config/*.secret"],
  "reveal": ["STRIPE_PUBLISHABLE_KEY"],
  "envFiles": [".env", ".env.test"],
  "aws": ["prod/db", "prod/api-key=API_KEY"]
}
```

## Known limits

- The Guard sees the literal command: `python -c "open('.env')"` or `$(printf '.e''nv')` pass it. The hard layer (the `Read(...)` deny rules `setup hooks` writes) and the sandbox are the boundary for those; masking covers whatever a Guarded Run prints.
- A Secret File tracked by git leaks through `git diff` / `git log -p`, and through `git grep` over an all-wildcard pathspec (`'scripts/**'`, which git expands itself); secrets-axi warns in the home view, it cannot cover it.
- A child of a Guarded Run can read the Secret File itself; Masking still covers what it prints. A value the Runner did not inject (a different Secret File the child reads on its own) is not masked, so load it through `run` too.
- Masking is by substring: values under four characters are not masked, and a short or common value that is not a Reveal Key can hit unrelated output (`secrets-axi policy add reveal LOG_FORMAT` fixes one such key). Encoded forms (base64, URL-encoded) are not masked yet.
- Membership of a Secret File is by name; a secret in an unnamed file is not seen (content sniffing is deferred).
- 0.1 resolves plain `.env` and AWS. `op`, `doppler`, `dotenvx` and `infisical` are detected and reported as "not supported yet"; the OpenCode plugin and Windows are deferred.

## Development

```sh
corepack pnpm install
corepack pnpm run check   # typecheck, tests, build, skill freshness
```

`skills/secrets-axi/SKILL.md` is generated: `corepack pnpm run build:skill`. See `PLAN.md` for the spec, `GLOSSARY.md` for the vocabulary and `docs/adr/` for the design decisions (the hook is the nudge and masking is the boundary; deny with a Hint instead of rewriting; sources resolve and the Runner spawns).

Fixture secrets in tests are obviously fake (`FAKE_...`) and never real values; every test asserts they do not appear in any output.

<!-- axi-tools:start -->
## Other AXI tools

- [`atl-axi`](https://github.com/cmosgh/atl-axi): Atlassian Jira Cloud CLI for agents
- [`bb-axi`](https://github.com/cmosgh/bb-axi): Bitbucket Cloud CLI for agents
- [`hetzner-axi`](https://github.com/cmosgh/hetzner-axi): Hetzner Cloud CLI for agents
- [`mongo-axi`](https://github.com/cmosgh/mongo-axi): Read-only MongoDB CLI for agents, plus `mongo-rw-axi` (write-capable MongoDB CLI for agents, loopback hosts only)
- [`mysql-axi`](https://github.com/cmosgh/mysql-axi): Read-only MySQL CLI for agents, plus `mysql-rw-axi` (write-capable MySQL CLI for agents, loopback hosts only)
- [`ts-axi`](https://github.com/cmosgh/ts-axi): TypeScript symbol CLI for agents
<!-- axi-tools:end -->

## License

MIT
