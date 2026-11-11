# secrets-axi - contributor notes for agents

AXI-compliant CLI that keeps secret values out of agent transcripts: a Guard hook that denies secret reads with a Hint, and a Runner that injects secrets into a child and masks its output. Read the AXI principles (https://axi.md) before changing output. `PLAN.md` is the spec, `GLOSSARY.md` the vocabulary, `docs/adr/` the decisions.

- **Masking is the boundary, the hook is the nudge** (ADR 0001). Never add a flag that disables masking. Never widen the hook with heuristics about intent: every Guard decision comes from a listable Policy entry and `secrets-axi check` must be able to explain it.
- **Secret values never reach stdout.** No command prints a value except for Reveal Keys. Error messages, hints and debug output include names and paths only. Tests assert the absence of fixture values in every output.
- **Deny, never `ask`; rewrite only Recursive Search** (ADR 0002). A Hint is at most two lines with the exact replacement command.
- **Sources resolve, the Runner spawns** (ADR 0003). A Secret Source returns a `Map<string, string>`; it never executes the user's command.
- **Hook entry is zero-dependency.** `src/hook/` imports `node:` builtins and the policy only; `test/hook-latency.test.ts` pins the budget. Anything heavier goes to the CLI side.
- **Output is the product.** TOON via `block()`/`helpBlock()`/`out()` in `src/render.ts`; 3-4 default fields, extras behind `--fields`; `test/token-budget.json` pins representative outputs.
- **Every flag is declared** in `parseArgs()`; usage errors are `VALIDATION_ERROR` (exit 2).
- **Writes:** the only files secrets-axi writes are the Secret File named in `set`/`unset` (in place, that key only), `~/.config/secrets-axi/policy.json` via `policy set`, and the agents' hook/deny config via `setup` (own entries only). Never a file inside a repository besides the one named in `set`/`unset`.
- **Policy layers:** built-in → user → repository; a repository layer can add and reveal, never remove a Secret File or Secret Fetch pattern.
- Tests: `test/unit.test.ts` (pure logic: policy merge, tokenizer, masker, env parser), `test/guard.test.ts` (hook decisions over synthetic calls), `test/commands.test.ts` (CLI via `main()` over `test/fixtures/`), `test/setup.test.ts` (HOME in a temp dir, never the real agent config). Fixture secrets are obviously fake (`FAKE_...`) and never real values.
- `pnpm run check` must pass. `skills/secrets-axi/SKILL.md` is generated: `pnpm run build:skill`.
