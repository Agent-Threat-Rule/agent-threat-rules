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
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

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
