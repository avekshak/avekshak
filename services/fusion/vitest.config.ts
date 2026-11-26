import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      provider: "v8",
      reporter: ["lcov", "text"],
      all: true,
      include: ["src/**/*.ts"],
      exclude: ["src/**/*.test.ts", "src/index.ts"],
      thresholds: {
        lines: 50,
        functions: 70,
        branches: 75,
        statements: 50,
      },
    },
  },
});
