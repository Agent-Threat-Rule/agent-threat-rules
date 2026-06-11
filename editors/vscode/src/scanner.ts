/**
 * ATR engine wrapper.
 *
 * Deliberately free of any 'vscode' imports so the headless smoke test
 * (test/engine-smoke.mjs) can load the exact module the extension uses,
 * including the same rules-directory resolution.
 *
 * The agent-threat-rules package is ESM-only; esbuild bundles it into
 * this module as CommonJS. The engine's own bundled-rules autodiscovery
 * relies on import.meta, which does not survive CJS bundling, so we
 * always pass an explicit rulesDir (a copy of the package's rules/ tree
 * placed next to the bundle at build time).
 */
import * as path from "node:path";
import * as fs from "node:fs";
import { ATREngine } from "agent-threat-rules";
import type { ScanResult } from "agent-threat-rules";

/**
 * Resolve the rules directory shipped inside the extension bundle.
 * esbuild.mjs copies node_modules/agent-threat-rules/rules to dist/rules,
 * so at runtime it sits next to the compiled bundle.
 */
export function resolveRulesDir(bundleDir: string): string {
  const candidate = path.join(bundleDir, "rules");
  if (!fs.existsSync(candidate)) {
    throw new Error(
      `ATR rules directory not found at ${candidate}. ` +
        "The extension package is incomplete; reinstall the extension."
    );
  }
  return candidate;
}

export class AtrScanner {
  private readonly engine: ATREngine;
  private loadPromise: Promise<number> | null = null;

  constructor(rulesDir: string) {
    this.engine = new ATREngine({ rulesDir });
  }

  /** Load rules once; concurrent callers share the same promise. */
  ensureLoaded(): Promise<number> {
    if (this.loadPromise === null) {
      this.loadPromise = this.engine.loadRules();
    }
    return this.loadPromise;
  }

  /** Scan file content and return the engine's full scan result. */
  async scan(content: string, filePath?: string): Promise<ScanResult> {
    await this.ensureLoaded();
    return this.engine.scanSkillFull(content, filePath);
  }
}
