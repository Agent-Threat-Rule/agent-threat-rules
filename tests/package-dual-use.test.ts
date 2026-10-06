/**
 * The package declares itself dual-use under the npm Dual-Use Content Policy
 * (https://docs.npmjs.com/policies/dual-use/). Rule files carry attack strings
 * by design, and npm's publish-time malware scanning blocked 4.1.1, 4.1.2 and
 * 4.1.3 without the declaration.
 *
 * Once a version ships with the declaration, npm rejects any later publish that
 * drops the `contentPolicy` field or the DISCLOSURE file, so these tests fail
 * here instead of at the registry.
 */
import { describe, it, expect } from "vitest";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";

const ROOT = resolve(__dirname, "..");
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as {
  contentPolicy?: { class?: string };
  files?: string[];
};

describe("npm dual-use declaration", () => {
  it("declares contentPolicy.class = dual-use", () => {
    expect(pkg.contentPolicy).toEqual({ class: "dual-use" });
  });

  it("ships a DISCLOSURE file at the package root", () => {
    expect(existsSync(join(ROOT, "DISCLOSURE"))).toBe(true);
    // npm always packs README and LICENSE; DISCLOSURE only travels if listed.
    expect(pkg.files).toContain("DISCLOSURE");
  });

  it("keeps DISCLOSURE plain text that names the dual-use content and its use", () => {
    const text = readFileSync(join(ROOT, "DISCLOSURE"), "utf8");
    expect(text.length).toBeGreaterThan(200);
    // Plain text only: no markup, no binary.
    expect(text).not.toMatch(/[\u0000-\u0008\u000e-\u001f]/);
    expect(text).not.toMatch(/<[a-z][^>]*>/i);
    expect(text).toMatch(/attack strings/i);
    expect(text).toMatch(/detect/i);
  });
});

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) return sourceFiles(full);
    return full.endsWith(".ts") ? [full] : [];
  });
}

// npm Trust & Safety reads DISCLOSURE against the code. These tie its factual
// claims to src/ so the two cannot drift apart silently.
describe("DISCLOSURE matches the code", () => {
  const disclosure = readFileSync(join(ROOT, "DISCLOSURE"), "utf8");

  it("names the endpoint the LLM judges fall back to", () => {
    const fallsBack = ["src/judges/openai-compatible.ts", "src/layer-integration.ts"].filter((f) =>
      readFileSync(join(ROOT, f), "utf8").includes("https://api.openai.com"),
    );
    if (fallsBack.length > 0) {
      expect(disclosure).toContain("https://api.openai.com");
    }
  });

  it("starts no process through a shell, as it says", () => {
    expect(disclosure).toMatch(/passed to a shell/);
    const childProcessImport = /import\s*(\{[^}]*\}|\*\s+as\s+\w+|\w+)\s*from\s*["'](?:node:)?child_process["']/g;
    const offenders = sourceFiles(join(ROOT, "src")).flatMap((file) => {
      const text = readFileSync(file, "utf8");
      const imports = [...text.matchAll(childProcessImport)].map((m) => m[1]!);
      const shellApi = imports.some((names) => !names.startsWith("{") || /\bexec(Sync)?\b/.test(names));
      return shellApi || /\bshell\s*:\s*true\b/.test(text) ? [relative(ROOT, file)] : [];
    });
    expect(offenders).toEqual([]);
  });
});
