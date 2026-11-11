# 3. Secret Sources resolve values, the Runner spawns the command

Date: 2026-11-11

## Status

Accepted

## Context

Secret managers ship their own `run` wrappers: `op run --env-file`, `doppler run`, `dotenvx run`, `infisical run`. Delegating execution to them is the least code. But Masking (ADR 0001) needs the values: `op run` masks on its own, the others do not, and none lets secrets-axi see what it injected. Behaviour would then differ by source, and the one thing the tool promises would hold for some sources only.

## Decision

A Secret Source only resolves: it returns the variables and values (`op inject`, `doppler secrets download --format json`, `dotenvx get --all`, the AWS SDK, our own `.env` parser). The Runner merges them, spawns the child once, and masks its output with one implementation. Secret values live in the Runner's memory, never on its stdout.

## Consequences

- One masker, one spawn path, identical guarantees for every source.
- Each source adapter is small (resolve to a map) and testable without running anything.
- The Runner must track each tool's export command and format; a tool changing its output format breaks resolution, not masking.
- Features of the vendor wrappers (their own masking, their caching) are not used.
