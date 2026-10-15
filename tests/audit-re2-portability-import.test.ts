/**
 * scripts/audit-re2-portability.ts is both a CLI and the home of scanPattern,
 * which the semantic lane imports to refuse non-RE2 fallbacks before writing a
 * rule. Importing it must not run the CLI: that would scan the whole rules
 * tree and print a report into whatever process imported it.
 */
import { describe, it, expect, vi } from "vitest";

describe("audit-re2-portability entrypoint guard", () => {
  it("exports scanPattern without running the audit on import", async () => {
    const write = vi.spyOn(process.stdout, "write");
    try {
      const mod = await import("../scripts/audit-re2-portability.js");
      expect(write).not.toHaveBeenCalled();
      expect(mod.scanPattern("(?!x)a").map((f) => f.cls)).toEqual(["lookaround"]);
      expect(mod.scanPattern("(?i)plain\\s+text")).toEqual([]);
    } finally {
      write.mockRestore();
    }
  });
});
