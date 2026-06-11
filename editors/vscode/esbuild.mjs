/**
 * Build script for the ATR Scan extension.
 *
 * Produces two CommonJS bundles:
 *   dist/extension.js  - the extension entry point (externals: vscode)
 *   dist/scanner.js    - the vscode-free scanner module, used by the
 *                        headless smoke test to exercise the exact same
 *                        engine + rules-dir resolution as the extension
 *
 * Also copies the agent-threat-rules bundled rules tree into dist/rules
 * so the engine can load rules at runtime without node_modules.
 *
 * The agent-threat-rules package is ESM-only; bundling to CJS triggers
 * an esbuild warning about import.meta in the engine's bundled-rules
 * autodiscovery. That path is never taken because the extension always
 * passes an explicit rulesDir (see src/scanner.ts).
 */
import { build, context } from "esbuild";
import { cpSync, rmSync, mkdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const distDir = join(here, "dist");
const rulesSource = join(here, "node_modules", "agent-threat-rules", "rules");
const rulesTarget = join(distDir, "rules");
const watch = process.argv.includes("--watch");

const shared = {
  bundle: true,
  format: "cjs",
  platform: "node",
  target: "node18",
  sourcemap: true,
  logLevel: "info",
  // Optional engine capabilities loaded via dynamic import only;
  // never used by this extension, so keep them out of the bundle.
  external: ["vscode", "@xenova/transformers", "@modelcontextprotocol/sdk"],
};

const builds = [
  {
    ...shared,
    entryPoints: [join(here, "src", "extension.ts")],
    outfile: join(distDir, "extension.js"),
  },
  {
    ...shared,
    entryPoints: [join(here, "src", "scanner.ts")],
    outfile: join(distDir, "scanner.js"),
  },
];

function copyRules() {
  if (!existsSync(rulesSource)) {
    throw new Error(
      `Rules source not found: ${rulesSource}. Run npm install first.`
    );
  }
  rmSync(rulesTarget, { recursive: true, force: true });
  mkdirSync(distDir, { recursive: true });
  cpSync(rulesSource, rulesTarget, { recursive: true });
  console.log(`Copied rules: ${rulesSource} -> ${rulesTarget}`);
}

async function run() {
  copyRules();
  if (watch) {
    const contexts = await Promise.all(builds.map((cfg) => context(cfg)));
    await Promise.all(contexts.map((ctx) => ctx.watch()));
    console.log("Watching for changes...");
    return;
  }
  await Promise.all(builds.map((cfg) => build(cfg)));
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
