/**
 * Tests for src/corpus/security-content.ts — 資安教材分段標籤的防濫用閘。
 *
 * THE FAILURE MODE THESE TESTS EXIST TO PREVENT
 *
 * benign gate 對 776 條會 fire 的規則量出 14,561 個 FP。收緊規則的人一致回報
 * 殘留 FP 是滲透測試教材逐字寫的 `' OR '1'='1` / `/etc/passwd`。於是很自然會想:
 * 「那些不是一般 benign,分流出去就好」。
 *
 * 那個念頭就是這個檔案要擋的東西。**把難的樣本重新歸類讓頭條數字變好看,是洗白,
 * 不是修正。**而且它比一般缺陷更難抓,因為它偽裝成「語料治理」。
 *
 * 這個 repo 已經處理過同一種誘惑並定下政策
 * (docs/research/precision-repair-broad-rules-2026-06-21.md):
 *   - 86 條真越獄樣本被標成 benign → 標籤錯誤 → 隔離。
 *   - 675 條 dual-use 模板 → 不是攻擊 → **留在 benign gate**,規則對它們開火就是真 FP。
 * 資安教材屬於後者。所以判準只准「標記」,不准「移除」。
 *
 * 四道斷言,對應四種濫用方式:
 *   1. 預算 — 判準被放寬成掃地機(標記率暴增)。
 *   2. 洗白 — 判準把真攻擊也標成「教材」。
 *   3. 結果導向 — 判準看規則的 FP 結果反推,把礙事的樣本歸到另一類。
 *   4. 移除 — 分段被拿去縮小語料 / 改變 gate 的 clean·dirty 判定。
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { load } from "js-yaml";
import {
  classifySecurityContent,
  MIN_TOPIC_MARKERS,
  SECURITY_CONTENT_BUDGET,
  LAUNDERING_CEILING,
} from "../src/corpus/security-content.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CLASSIFIER_SRC = join(REPO_ROOT, "src/corpus/security-content.ts");
const GATE_SRC = join(REPO_ROOT, "scripts/gate-promotion-fp.ts");

/** 與 scripts/gate-promotion-fp.ts 完全相同的語料集合。 */
const CORPORA = [
  join(REPO_ROOT, "data/skill-benchmark/benign"),
  join(REPO_ROOT, "data/benign-corpus-extended"),
  join(REPO_ROOT, "data/benign-code"),
];

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    const full = join(dir, e);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else if (e.endsWith(".jsonl") || e.endsWith(".md")) out.push(full);
  }
  return out;
}

function benignSamples(): string[] {
  const out: string[] = [];
  for (const c of CORPORA) {
    if (!existsSync(c)) continue;
    for (const f of statSync(c).isDirectory() ? walk(c) : [c]) {
      const raw = readFileSync(f, "utf-8");
      if (f.endsWith(".md")) {
        out.push(raw);
        continue;
      }
      for (const line of raw.split("\n")) {
        const t = line.trim();
        if (!t) continue;
        try {
          const o = JSON.parse(t) as { text?: string };
          if (typeof o.text === "string" && o.text.length > 0) out.push(o.text);
        } catch {
          /* not a sample line */
        }
      }
    }
  }
  return out;
}

/** 全 repo 規則自己宣告的 true positives — 真攻擊樣本。 */
function ruleTruePositives(): string[] {
  const out: string[] = [];
  const files = execFileSync("git", ["ls-files", "rules/"], {
    cwd: REPO_ROOT,
    encoding: "utf-8",
    maxBuffer: 64 * 1024 * 1024,
  })
    .split("\n")
    .filter((f) => f.endsWith(".yaml") || f.endsWith(".yml"));
  for (const f of files) {
    let d: unknown;
    try {
      d = load(readFileSync(join(REPO_ROOT, f), "utf-8"));
    } catch {
      continue;
    }
    const doc = d as { test_cases?: { true_positives?: unknown[] } };
    for (const t of doc?.test_cases?.true_positives ?? []) {
      const txt =
        typeof t === "string" ? t : ((t as { input?: unknown })?.input ?? "");
      if (typeof txt === "string" && txt.length > 0) out.push(txt);
    }
  }
  return out;
}

describe("security-content 判準:預算", () => {
  it("被標為資安內容的樣本不得超過 benign gate 語料的 SECURITY_CONTENT_BUDGET", () => {
    const samples = benignSamples();
    expect(samples.length).toBeGreaterThan(5000); // 語料本身沒被縮小

    const labeled = samples.filter(
      (t) => classifySecurityContent(t).label === "security-content",
    ).length;
    const fraction = labeled / samples.length;

    // 2026-08-07 實測 37/5352 = 0.69%。上限 2% 給語料成長留餘裕,
    // 但任何把判準放寬成「凡是提到資安就分流」的改動都會撞到這條線。
    expect(fraction).toBeLessThanOrEqual(SECURITY_CONTENT_BUDGET);
  });

  it("判準要窄到有意義:單一訊號不足以被標記", () => {
    // 只有主題,沒有逐字 payload
    expect(
      classifySecurityContent(
        "Our OWASP threat model review found no SQL injection.",
      ).label,
    ).toBe("general");
    // 只有 payload,沒有資安主題
    expect(classifySecurityContent("open('../../config/app.json')").label).toBe(
      "general",
    );
    // 兩者兼具才算
    const both = classifySecurityContent(
      "OWASP penetration testing lab: the classic tautology payload ' OR '1'='1 bypasses the login form; remediation is parameterised queries.",
    );
    expect(both.label).toBe("security-content");
    expect(both.topicMarkers).toBeGreaterThanOrEqual(MIN_TOPIC_MARKERS);
    expect(both.payloads.length).toBeGreaterThan(0);
  });
});

describe("security-content 判準:洗白偵測", () => {
  it("真攻擊樣本(全 repo 規則的 true_positives)不得被大量標成資安內容", () => {
    const tps = ruleTruePositives();
    expect(tps.length).toBeGreaterThan(3000);
    const labeled = tps.filter(
      (t) => classifySecurityContent(t).label === "security-content",
    ).length;
    // 2026-08-07 實測 1/3805 = 0.03%。一支會把真攻擊標成「教材」的判準就是洗白機器。
    expect(labeled / tps.length).toBeLessThanOrEqual(LAUNDERING_CEILING);
  });

  it("garak in-the-wild 越獄語料不得被標成資安內容", () => {
    const p = join(REPO_ROOT, "data/test-corpora/garak-full/inthewild.json");
    if (!existsSync(p)) return; // 語料不在這個 checkout 裡就跳過
    const prompts = (
      JSON.parse(readFileSync(p, "utf-8")) as { prompts: string[] }
    ).prompts;
    expect(prompts.length).toBeGreaterThan(100);
    const labeled = prompts.filter(
      (t) => classifySecurityContent(t).label === "security-content",
    ).length;
    // 2026-08-07 實測 0/650。
    expect(labeled / prompts.length).toBeLessThanOrEqual(LAUNDERING_CEILING);
  });
});

describe("security-content 判準:結構性防濫用", () => {
  it("判準不得看見規則、引擎或 FP 結果", () => {
    const src = readFileSync(CLASSIFIER_SRC, "utf-8");
    // 註解裡會提到 ATR-2026-xxxxx,所以只看 import 行與可執行識別字。
    const imports = src.split("\n").filter((l) => /^\s*import\b/.test(l));
    expect(imports).toEqual([]); // 零依賴 = 拿不到引擎,也拿不到 FP 計數
    const code = src
      .split("\n")
      .filter((l) => !/^\s*(\*|\/\/|\/\*)/.test(l))
      .join("\n");
    for (const forbidden of [
      "ATREngine",
      "engine.",
      "fpCount",
      "matchedRuleIds",
      "rule.id",
    ]) {
      expect(code).not.toContain(forbidden);
    }
  });

  it("判準沒有移除樣本的出口", () => {
    const src = readFileSync(CLASSIFIER_SRC, "utf-8");
    const code = src
      .split("\n")
      .filter((l) => !/^\s*(\*|\/\/|\/\*)/.test(l))
      .join("\n");
    for (const forbidden of [
      ".filter(",
      ".splice(",
      "unlinkSync",
      "writeFileSync",
      "quarantine",
    ]) {
      expect(code).not.toContain(forbidden);
    }
  });

  it("gate 的 clean·dirty 判定與離開碼不得讀取分段標籤", () => {
    const gate = readFileSync(GATE_SRC, "utf-8");
    // partitionByFp 決定 clean/dirty;resolveExitCode 決定 PR 紅綠。
    // 兩者的引數都不得出現 securityCounts —— 分段只能進 report 與 emit 的字串。
    const partitionCall = /partitionByFp\(([^)]*)\)/g;
    for (const m of gate.matchAll(partitionCall)) {
      expect(m[1] ?? "").not.toContain("security");
    }
    const exitCall = /resolveExitCode\(([^)]*)\)/g;
    for (const m of gate.matchAll(exitCall)) {
      expect(m[1] ?? "").not.toContain("security");
    }
  });

  it("分段是加法而非減法:general + security 必須等於總數", () => {
    const samples = benignSamples();
    const sec = samples.filter(
      (t) => classifySecurityContent(t).label === "security-content",
    ).length;
    const gen = samples.filter(
      (t) => classifySecurityContent(t).label === "general",
    ).length;
    expect(sec + gen).toBe(samples.length);
  });
});
