# 1. The hook is the nudge, masking is the boundary

Date: 2026-11-11

## Status

Accepted

## Context

Agent runtimes expose a pre-tool hook (`PreToolUse` in Claude Code and Codex, `tool.execute.before` in OpenCode) that can deny a call with a reason. Their documentation calls hooks best-effort: the hook sees the literal command text, some tool paths skip it, and a read hidden in a subprocess (`python -c "open('.env')"`) passes it. The hard controls, permission deny rules and the OS sandbox, stop reads but cannot explain what to do instead, and neither stops a program that was legitimately started with secrets from printing them.

Two places could be "the" security line:

- **The hook**: block every way to read a Secret File. Unwinnable against a shell; every miss is a leak.
- **The Runner's output**: whatever runs, every injected value is replaced in stdout/stderr before the agent sees it (amended 0.1.4: except the values of Reveal Keys, which the Policy already declares public).

## Decision

Masking in the Runner is the boundary: it is unconditional, cannot be disabled, and covers every value the Runner injected regardless of how the child obtained or printed it. The Guard hook is the nudge: it denies the obvious reads with a Hint that names the Runner command, so the agent reaches the boundary instead of the file. `setup hooks` additionally installs the agent's own deny rules as the hard layer for reads the hook cannot see.

## Consequences

- The hook stays simple and deterministic (token rules, listable), because it does not have to be complete.
- Values the Runner never injected (a Secret File the child reads on its own that is not the loaded env file) are not masked; the home view lists such files so the agent loads them through `run` too.
- Masking by substring can hit unrelated output when a value is short or common; values under four characters and plain config literals (`true`, `false`, `null`, ...) are not masked and this is accepted.
- Adding a new agent runtime means writing a thin hook adapter, not re-deriving the security model.
