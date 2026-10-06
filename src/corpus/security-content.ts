/**
 * security-content.ts — 把 benign gate 的樣本標成「一般 benign」與「資安內容」兩段。
 *
 * WHY THIS EXISTS
 *
 * benign gate 的用途是量「規則在 agent 會讀到的一般內容上誤報多少」。語料裡確實
 * 混著滲透測試教材、合規報告、安全稽核 skill —— 這類文件逐字寫著 `' OR '1'='1`、
 * `/etc/passwd`、`; DROP TABLE`。一條 regex 規則看到那些字串就開火,而那份文件
 * 本身沒有攻擊任何人。
 *
 * WHAT THIS IS NOT
 *
 * **這個模組不會、也不能從語料裡拿掉任何樣本。**它只回傳標籤。gate 的頭條數字
 * 仍然是全語料的 FP 總數,分段數字是額外資訊,不是替代品。
 *
 * 理由寫在 docs/research/precision-repair-broad-rules-2026-06-21.md 定下的政策裡:
 *
 *   > A dual-use security skill that legitimately contains attack techniques is
 *   > not a false positive to suppress by blunting the rule; it is an advisory-
 *   > tier signal the consumer decides on.
 *
 * 那次稽核把 benign 語料分成兩群並分開處置,而且只有其中一群被隔離:
 *   - 86 條「真越獄樣本被標成 benign」→ 標籤錯誤 → 隔離(它們同時是 dan-corpus
 *     的 true positive,一份母體兩個相反標籤)。
 *   - 675 條 dual-use SEO 模板 → **不是**攻擊 → 留在 benign gate,規則對它們開火
 *     就是真 FP。
 *
 * 本模組處理的是第二群的近親:資安教材。政策一致 —— 留著,但分開報。
 *
 * ANTI-ABUSE(這是本檔最重要的部分)
 *
 * 「把難的樣本標成另一類讓頭條數字變好看」是洗白。四道防線:
 *
 *   1. **只標記,不移除。** 本模組沒有 delete/filter/exclude 的出口。
 *   2. **判準與規則結果無關。** classify() 只吃樣本文字,拿不到引擎、規則 id、
 *      FP 計數。判準不能被「哪些樣本害我 FP」反推調整。
 *      tests 會斷言本檔不 import 引擎。
 *   3. **窄口徑。** 要同時滿足「逐字攻擊 payload」與「≥2 個相異資安主題標記」
 *      才算資安內容。只提 OWASP 不算,只出現 `../../` 也不算。
 *   4. **預算上限 + 洗白偵測。** ratchet 測試斷言(a)被標記的比例不得超過語料的
 *      SECURITY_CONTENT_BUDGET,(b)同一支判準跑在真攻擊語料上,標記率必須低於
 *      LAUNDERING_CEILING —— 一支會把真攻擊也標成「教材」的判準就是洗白機器。
 */

/** 逐字攻擊 payload:文件把可執行的攻擊字串原樣抄進去。 */
const PAYLOAD_PATTERNS: readonly RegExp[] = [
  // SQL injection
  /'\s*or\s*'?1'?\s*=\s*'?1/i,
  /\bor\s+1\s*=\s*1\s*(--|#|;)/i,
  /\bunion\s+(all\s+)?select\b/i,
  /\bdrop\s+table\b/i,
  /\bxp_cmdshell\b/i,
  // path traversal / sensitive files
  /\/etc\/(passwd|shadow)\b/i,
  /(\.\.[/\\]){2,}/,
  /%2e%2e(%2f|%5c)/i,
  /\bid_rsa\b/i,
  // XSS
  /<script>\s*alert\s*\(/i,
  /\bjavascript:\s*alert\s*\(/i,
  /\bonerror\s*=\s*["']?alert\s*\(/i,
  // shell / reverse shell
  /\brm\s+-rf\s+\/(?!\w)/,
  /\bnc\s+-[a-z]*e[a-z]*\s+\/bin\/(ba)?sh/i,
  /\/bin\/(ba)?sh\s+-i\s+>&/i,
  /\bbase64\s+-d\s*\|\s*(ba)?sh\b/i,
  // offensive tooling invoked with flags (not the bare product name)
  /\bsqlmap\s+-/i,
  /\bmsfvenom\s+-/i,
  /\bnmap\s+-s[A-Za-z]/,
  /\bhydra\s+-[lL]\b/,
  /\bjohn\s+--wordlist/i,
  /\bhashcat\s+-m\s+\d/i,
  /\bmimikatz\b/i,
];

/**
 * 資安主題標記。需要 ≥2 個**相異**標記才算「這份文件在談資安」——
 * 一次提及可能只是順帶,兩個以上相異標記才是主題。
 */
const TOPIC_PATTERNS: readonly RegExp[] = [
  /\bpenetration\s+test(ing|er)?\b/i,
  /\bpentest(ing)?\b/i,
  /\bred[\s-]?team(ing)?\b/i,
  /\bbug\s+bounty\b/i,
  /\bvulnerability\s+(scan|assessment|research|disclosure)/i,
  /\bowasp\b/i,
  /\bcve-\d{4}-\d+/i,
  /\bcwe-\d+/i,
  /\bmitre\s+att&?ck\b/i,
  /\bsecurity\s+(audit|review|assessment|hardening)\b/i,
  /\bthreat\s+model(ing|s)?\b/i,
  /\battack\s+(surface|vector|chain|tree)\b/i,
  /\bsql\s+injection\b/i,
  /\bcross[\s-]site\s+scripting\b|\bxss\b/i,
  /\bcsrf\b|\bssrf\b/i,
  /\bprivilege\s+escalation\b/i,
  /\breverse\s+shell\b/i,
  /\bmalware\s+analysis\b/i,
  /\bincident\s+response\b/i,
  /\bremediation\b/i,
  /\bmitigation[s]?\b/i,
  /\bsecure\s+coding\b/i,
  /\bcis\s+benchmark\b/i,
  /\bnist\s+(sp\s?)?800/i,
  /\bpci[\s-]?dss\b/i,
  /\bsoc\s?2\b/i,
  /\bsast\b|\bdast\b/i,
  /\bexploit(ation)?\b/i,
];

export type SecurityContentLabel = "general" | "security-content";

export interface SecurityContentVerdict {
  readonly label: SecurityContentLabel;
  /** 命中的逐字 payload pattern(以 regex source 表示,方便人審)。 */
  readonly payloads: readonly string[];
  /** 命中的相異資安主題標記數。 */
  readonly topicMarkers: number;
}

/**
 * 唯一的判準。輸入只有樣本文字 —— 沒有規則、沒有引擎、沒有 FP 計數。
 *
 * label = "security-content" ⟺ 逐字 payload ≥1 **且** 相異主題標記 ≥ MIN_TOPIC_MARKERS。
 */
export const MIN_TOPIC_MARKERS = 2;

export function classifySecurityContent(text: string): SecurityContentVerdict {
  const payloads: string[] = [];
  for (const p of PAYLOAD_PATTERNS) if (p.test(text)) payloads.push(p.source);

  let topicMarkers = 0;
  for (const t of TOPIC_PATTERNS) if (t.test(text)) topicMarkers += 1;

  const label: SecurityContentLabel =
    payloads.length > 0 && topicMarkers >= MIN_TOPIC_MARKERS
      ? "security-content"
      : "general";
  return { label, payloads, topicMarkers };
}

/**
 * 被標為資安內容的樣本佔語料的比例上限。超過就是判準被放寬成掃地機。
 * 2026-08-07 實測 = 0.69%(37/5352)。上限 2% 給語料成長留餘裕。
 */
export const SECURITY_CONTENT_BUDGET = 0.02;

/**
 * 同一支判準跑在**真攻擊**語料上的標記率上限。真攻擊被標成「教材」= 洗白。
 *
 * 這個數字是實測校準出來的,不是憑感覺挑的。2026-08-07 乾淨判準實測:
 * 規則自宣告 true_positives 1/3805 = 0.03%、garak in-the-wild 0/650 = 0.00%。
 *
 * 校準過程:先訂 5%,然後刻意把攻擊語言(「ignore all previous instructions」、
 * 「do anything now」、jailbreak/DAN/prompt injection)偷渡進 payload 與主題清單 ——
 * 這是最典型的洗白手法。結果 garak 標記率跳到 3.85%,**5% 沒有咬住**。
 * 上限因此收到 1%:窄判準在真攻擊上本來就該是零,任何有意義的攻擊掃入都會撞線。
 */
export const LAUNDERING_CEILING = 0.01;
