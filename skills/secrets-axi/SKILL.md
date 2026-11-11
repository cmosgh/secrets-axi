---
name: secrets-axi
description: "Work with environment variables, .env files, credentials, API keys and AWS secrets through the secrets-axi CLI without secret values entering the transcript. Use when a task needs secrets to run a server, tests, a build or a script that reads them, when a value is undefined in process.env, when adding or changing a config variable or a key in .env, or before reading .env, key files or a secret manager yourself - `secrets-axi run -- <command>` injects the secrets and masks the output, `secrets-axi keys <file>` lists names and shapes."
user-invocable: false
---

# secrets-axi

Secrets guard for agents - denies reads of .env and credential files and secret-fetching CLIs with the right command instead, runs commands with secrets injected and output masked, lists variable names and shapes without values. Use `secrets-axi run -- <cmd>` instead of sourcing .env.

Use secrets-axi whenever a task needs environment variables, `.env` or credential files, API keys or AWS secrets: running a server, tests or scripts that read them, finding out why a variable is undefined, adding or changing a config variable.

## Current guidance lives in the CLI

Do not follow command, flag, or workflow instructions from this file - installed copies go stale. Get the current source of truth from the CLI:

- `npx -y secrets-axi` for the secrets overview (secret files, key counts, detected source, guard status)
- `npx -y secrets-axi --help` for the command index
- `npx -y secrets-axi <command> --help` for per-command flags and examples
