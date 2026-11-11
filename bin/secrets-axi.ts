#!/usr/bin/env node
import { tryFastPath } from "axi-sdk-js/fast-path";
import { VERSION } from "../src/version.js";

const argv = process.argv.slice(2);
// The hook runs on every agent tool call: load only the guard, never the CLI graph.
if (argv[0] === "hook") {
  const { runHook } = await import("../src/hook/entry.js");
  process.exitCode = await runHook();
} else if (!tryFastPath(argv, { version: VERSION })) {
  const { main } = await import("../src/cli.js");
  await main();
}
