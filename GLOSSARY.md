# Glossary

Terms used by secrets-axi, its output and its documentation. Implementation details do not belong here.

## Secret File

A file whose content is presumed to hold credentials, named by a built-in list that the Policy can extend: `.env` and `.env.*` (not `.env.example`, `.env.sample`, `.env.template`), `.secrets*`, private key files (`*.pem`, `*.key`, `id_*` without `.pub`), and well-known home files (`~/.aws/credentials`, `~/.ssh/id_*`, `~/.npmrc`, `~/.netrc`, `~/.docker/config.json`, `~/.kube/config`, `~/.config/gh/hosts.yml`). Membership is decided by name, never by content.

## Secret Fetch

A command whose normal output is a secret value: `aws secretsmanager get-secret-value`, `aws ssm get-parameter --with-decryption`, `op read`, `vault kv get`, `doppler secrets`, and the like. Named by a built-in list the Policy can extend. Listing or describing secrets (names only) is not a Secret Fetch.

## Guard

The part of secrets-axi that runs before an agent's tool call and decides whether the call reads a Secret File or performs a Secret Fetch. A Guard decision is **deny** (with a Hint), **rewrite** (Recursive Search only) or **pass**. The Guard decides from the literal call, deterministically; it never judges intent.

## Hint

The text of a deny decision: at most two lines naming the exact replacement command, with real paths and names filled in.

## Allowed Consumer

A program that loads a Secret File without printing it, so naming the file on its command line is not a read: `docker ... --env-file`, `dotenv -e`, `dotenvx run`, `op run --env-file`, and secrets-axi itself. Named by a built-in list the Policy can extend.

## Recursive Search

A search over a directory tree (the agent's Grep tool, `grep -r`, `rg`, `ag`) that would print matching lines of any Secret File below it. The one case the Guard rewrites instead of denying: the Secret File patterns are added as exclusions.

## Runner

The part of secrets-axi an agent calls on purpose: a Guarded Run, a key listing, an in-place edit of a Secret File, a dry run of the Guard, or a print of the Policy.

## Guarded Run

Running a command with secrets injected into its environment, where the agent never sees the values: the Secret Source resolves them, the Runner spawns the command, and Masking covers its output.

## Secret Source

Where a Guarded Run gets its values from, detected from what is in the repository: a plain `.env` file, `op://` references, a Doppler or Infisical project, a dotenvx-encrypted `.env`, or AWS Secrets Manager / SSM entries named by the Policy. A Secret Source resolves values; it never runs the command.

## Masking

Replacing every injected value in a Guarded Run's output with the name of its variable, `<DB_PASSWORD>`. Values shorter than four characters are not masked. Masking cannot be switched off.

## Reveal Key

A variable whose value is not secret and may be shown by a key listing: a built-in list of public names (`NODE_ENV`, `PORT`, `HOST`, ...) the Policy can extend.

## Key listing

The safe view of a Secret File: each variable's name, whether it is set or empty, and the shape of its value (length and character class). Values appear only for Reveal Keys.

## Policy

The lists the Guard and Runner decide from: Secret Files, Secret Fetches, Allowed Consumers, Reveal Keys, env files to load, AWS entries. Three layers: built-in, user, repository. A repository layer may add to any list and may add Reveal Keys; it can never remove a Secret File or Secret Fetch pattern.
