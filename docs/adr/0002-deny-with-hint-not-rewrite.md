# 2. Deny with a Hint, do not rewrite the call

Date: 2026-11-11

## Status

Accepted

## Context

Claude Code and Codex hooks can return `allow` with `updatedInput`, replacing the agent's call before it runs: `cat .env` could silently become `secrets-axi keys .env`. That removes a round trip. It also means the agent reasons from a result it did not ask for, and the transcript shows a command that never ran. A `deny` with a reason costs one extra tool call but keeps the agent's model of what happened truthful. Claude Code also offers `ask` (a human approves once); Codex rejects `ask` and lets the call proceed.

## Decision

The Guard denies with a Hint (at most two lines, the exact replacement command with real values). It never returns `ask`. The single rewrite is Recursive Search: a directory-wide grep gets the Secret File patterns appended as exclusions, because denying `grep -r TODO .` would make the Guard unusable and the rewritten call still does what the agent asked.

## Consequences

- Every denial is one wasted tool call; the Hint makes the next call the right one.
- Behaviour is identical across agents (`deny` is supported everywhere).
- Rewritten searches show the exclusions in the command the agent sees, so the omission is visible, not silent.
- A human who wants a raw value uses their own terminal; the tool offers no override path.
