/**
 * Tests for scripts/lib/rule-ids.ts — how an unattended lane picks rule ids
 * and how it notices ids that already collide.
 *
 * fn-mine allocated "highest id on disk + 1". Disk is main plus its own rolling
 * branch, so another lane's open PR (auto-semantic/rolling held 02846–02853
 * while main stopped at 02845) was invisible, and the next fn-mine batch got
 * 02846 again. Whichever PR merged second went red on "Duplicate rule ID", and
 * the miner kept stacking rules onto it because check-rules-safety only looks
 * for duplicates among the files a PR adds.
 */
import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  topLevelRuleId,
  readRuleFileIds,
  duplicateRuleIds,
  describeDuplicateRuleIds,
  usedRuleSeqs,
  nextRuleSeq,
  formatRuleId,
} from "../scripts/lib/rule-ids.js";

const tmpDirs: string[] = [];
afterEach(() => {
  for (const d of tmpDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function repoWith(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), "rule-ids-test-"));
  tmpDirs.push(root);
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(join(root, rel, ".."), { recursive: true });
    writeFileSync(join(root, rel), body);
  }
  return root;
}

describe("topLevelRuleId", () => {
  it("reads the top-level id in every spelling the rule files use", () => {
    expect(topLevelRuleId("title: x\nid: ATR-2026-00003\nstatus: stable\n")).toBe("ATR-2026-00003");
    expect(topLevelRuleId('id: "ATR-2026-00004"\n')).toBe("ATR-2026-00004");
    expect(topLevelRuleId("id: 'ATR-2026-00005'  # renumbered\n")).toBe("ATR-2026-00005");
  });

  it("ignores nested ids and files without one", () => {
    expect(topLevelRuleId("meta:\n  id: ATR-2026-00006\n")).toBeNull();
    expect(topLevelRuleId("title: no id here\n")).toBeNull();
  });
});

describe("readRuleFileIds", () => {
  it("lists every rule file under the directory with its id, paths relative to the root", () => {
    const root = repoWith({
      "rules/a/ATR-2026-00010-x.yaml": "id: ATR-2026-00010\n",
      "rules/b/deep/ATR-2026-00011-y.yml": "id: ATR-2026-00011\n",
      "rules/b/notes.md": "id: ATR-2026-00099\n",
    });
    const got = readRuleFileIds(root, "rules").map((r) => `${r.file}=${r.id}`).sort();
    expect(got).toEqual(["rules/a/ATR-2026-00010-x.yaml=ATR-2026-00010", "rules/b/deep/ATR-2026-00011-y.yml=ATR-2026-00011"]);
  });
});

describe("duplicateRuleIds", () => {
  it("names every file that declares an id another file declares too", () => {
    const dups = duplicateRuleIds([
      { file: "rules/x/ATR-2026-02846-main.yaml", id: "ATR-2026-02846" },
      { file: "rules/y/ATR-2026-02846-mined.yaml", id: "ATR-2026-02846" },
      { file: "rules/y/ATR-2026-02847-ok.yaml", id: "ATR-2026-02847" },
      { file: "rules/y/no-id.yaml", id: null },
      { file: "rules/z/no-id-either.yaml", id: null },
    ]);
    expect([...dups.keys()]).toEqual(["ATR-2026-02846"]);
    expect(dups.get("ATR-2026-02846")).toEqual(["rules/x/ATR-2026-02846-main.yaml", "rules/y/ATR-2026-02846-mined.yaml"]);
  });

  it("says which files to renumber", () => {
    const msg = describeDuplicateRuleIds(
      new Map([["ATR-2026-02846", ["rules/x/a.yaml", "rules/y/b.yaml"]]]),
    );
    expect(msg).toContain("ATR-2026-02846");
    expect(msg).toContain("rules/x/a.yaml");
    expect(msg).toContain("rules/y/b.yaml");
  });
});

describe("usedRuleSeqs / nextRuleSeq", () => {
  const onDisk = [
    { file: "rules/x/ATR-2026-02844-a.yaml", id: "ATR-2026-02844" },
    { file: "rules/x/ATR-2026-02845-b.yaml", id: "ATR-2026-02845" },
  ];
  const otherLanePr = [2846, 2847, 2848, 2849, 2850, 2851, 2852, 2853].map(
    (n) => `rules/prompt-injection/ATR-2026-0${n}-semantic.yaml`,
  );

  it("skips past ids another lane's open PR holds, not just what is on disk", () => {
    expect(nextRuleSeq(usedRuleSeqs(onDisk, [], "2026"))).toBe(2846);
    expect(nextRuleSeq(usedRuleSeqs(onDisk, otherLanePr, "2026"))).toBe(2854);
  });

  it("counts a file name's id even when the file's id field says otherwise", () => {
    const seqs = usedRuleSeqs([{ file: "rules/x/ATR-2026-02900-renamed.yaml", id: "ATR-2026-00001" }], [], "2026");
    expect(nextRuleSeq(seqs)).toBe(2901);
  });

  it("ignores open-PR files outside rules/ and ids from another year", () => {
    const seqs = usedRuleSeqs(onDisk, ["docs/ATR-2026-09999-note.md", "rules/x/ATR-2025-05000-old.yaml"], "2026");
    expect(nextRuleSeq(seqs)).toBe(2846);
  });

  it("starts at 1 when nothing is used", () => {
    expect(nextRuleSeq([])).toBe(1);
  });

  it("formats ids the way rule files spell them", () => {
    expect(formatRuleId("2026", 2854)).toBe("ATR-2026-02854");
    expect(formatRuleId("2026", 7)).toBe("ATR-2026-00007");
  });
});
