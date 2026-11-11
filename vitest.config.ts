import { configDefaults, defineConfig } from "vitest/config";

// test/fixtures holds sample repositories, never tests to run.
export default defineConfig({
  test: { exclude: [...configDefaults.exclude, "test/fixtures/**"] },
});
