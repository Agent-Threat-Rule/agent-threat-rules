import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    testTimeout: 180_000,
    hookTimeout: 60_000,
    pool: 'threads',
    fileParallelism: false,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'text-summary', 'json-summary'],
      include: ['src/**/*.ts'],
      exclude: [
        'src/cli.ts',
        'src/mcp-server.ts',
        'src/mcp-tools/**',
        'src/index.ts',
        'src/types.ts',
        'src/rule-scaffolder.ts',
        'src/coverage-analyzer.ts',
        'src/skill-fingerprint.ts',
        'src/layer-integration.ts',
        'src/modules/semantic.ts',
        'src/modules/session.ts',
        'src/modules/index.ts',
      ],
      thresholds: {
        statements: 60,
        branches: 60,
        functions: 60,
        lines: 60,
      },
    },
  },
});
