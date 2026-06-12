// Pre-create the dist/ directory tree mirroring src/ before `tsc --build` runs.
//
// Why this exists: package.json has `composite: true` with no project
// references, so `tsc --build` emits in parallel. On a clean checkout (no
// dist/ yet), CI on Linux hit `error TS5033: ... ENOENT: mkdir 'dist/adapters'`
// because emit ordering tried to write dist/adapters/* before dist/ root
// existed. macOS readdir ordering happened to avoid it, so it only failed in CI.
//
// Mirroring the tree up front makes emit independent of ordering: every
// directory tsc writes into already exists. This runs via the npm `prebuild`
// lifecycle, so it also covers `npm ci` (which triggers `prepare` -> build).
import { mkdirSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

function mirror(srcDir, distDir) {
  mkdirSync(distDir, { recursive: true });
  for (const entry of readdirSync(srcDir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      mirror(join(srcDir, entry.name), join(distDir, entry.name));
    }
  }
}

mirror('src', 'dist');
