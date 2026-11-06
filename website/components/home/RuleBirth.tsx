import Link from "next/link";

export interface BirthRule {
  id: string;
  title: string;
  severity: string;
  maturity: string;
  category: string;
  date: string;
  truePositives: number;
  trueNegatives: number;
  mappings: string[];
  /** Fixed historical dates (UTC); the page that builds this cites their sources. */
  reported: string;
  mergedToMain: string;
  firstNpmVersion: string;
  firstNpmDate: string;
}

type B = { en: string; zh: string };

const STEPS: ReadonlyArray<{ key: string; label: B; head: B; body: B }> = [
  {
    key: "incident",
    label: { en: "Incident", zh: "事件" },
    head: { en: "Someone finds a new way in", zh: "有人找到新的入口" },
    body: {
      en: "July 2026: Manifold Security reports that an Azure DevOps MCP server hands pull-request descriptions to the agent untouched. An HTML comment in the description is invisible on the web page. The agent reads it and does what it says, with the reviewer's own access.",
      zh: "2026 年 7 月，Manifold Security 回報：Azure DevOps 的 MCP 伺服器把 PR 描述原封不動交給 agent。描述裡藏一段 HTML 註解，網頁上看不到，agent 卻讀得到，還會用審查者自己的權限照做。",
    },
  },
  {
    key: "rule",
    label: { en: "Rule", zh: "規則" },
    head: { en: "It is written down once", zh: "寫下來，一次就好" },
    body: {
      en: "The attack becomes a rule with a permanent ID. It describes the shape of the attack, not the vendor, so the same trick is caught wherever it shows up.",
      zh: "這一招被寫成一條規則，拿到永久編號。規則描述的是攻擊的樣子，不是某一家廠商，所以同一招換個地方出現，一樣認得出來。",
    },
  },
  {
    key: "tests",
    label: { en: "Tests", zh: "測試" },
    head: { en: "It has to prove both ways", zh: "該抓的抓，不該抓的放" },
    body: {
      en: "Every rule carries examples it must catch and examples it must leave alone. CI reruns them on every pull request and every push to main.",
      zh: "每條規則都附上必須抓到的例子，也附上必須放過的例子。每個 PR、每次推上 main，CI 都會把這些例子重跑一遍。",
    },
  },
  {
    key: "release",
    label: { en: "Release", zh: "發布" },
    head: { en: "Everyone gets it", zh: "所有人一起拿到" },
    body: {
      en: "It ships in the next numbered release on npm. An agent that updates ATR gets the rule in the lanes its maturity allows. Nobody had to sign anything or pay for it.",
      zh: "它跟著下一個 npm 版號發布。更新了 ATR 的 agent 就拿得到這條規則，在它成熟度允許的車道裡跑。沒有人需要簽約，也不用付錢。",
    },
  },
];

/**
 * How one rule came to be, set out as a register: four entries, each with what
 * happened and the record that shows it. Static on purpose; the dates are the
 * point, and every one of them can be checked.
 */
export function RuleBirth({ locale, rule }: { locale: string; rule: BirthRule }) {
  const zh = locale === "zh";
  const pick = (b: B) => (zh ? b.zh : b.en);
  const record: Record<string, Array<[string, string]>> = {
    incident: [[zh ? "回報" : "Reported", rule.reported], [zh ? "回報者" : "Reporter", "Manifold Security"]],
    rule: [[zh ? "編號" : "ID", rule.id], [zh ? "規則日期" : "Rule dated", rule.date]],
    tests: [[zh ? "必須抓到" : "Must catch", String(rule.truePositives)], [zh ? "必須放過" : "Must leave alone", String(rule.trueNegatives)]],
    release: [[zh ? "合進 main" : "Reached main", rule.mergedToMain], [zh ? "npm 發布" : "Shipped on npm", `${rule.firstNpmDate} · ${rule.firstNpmVersion}`]],
  };

  return (
    <div>
      <ol className="border-t border-ink">
        {STEPS.map((s, i) => (
          <li key={s.key} className="grid md:grid-cols-[48px_1fr_260px] gap-x-8 gap-y-3 py-7 border-b border-fog">
            <span className="font-title text-[18px] text-stone" aria-hidden="true">{String(i + 1).padStart(2, "0")}</span>
            <div className="max-w-[620px]">
              <div className="text-[12.5px] text-stone">{pick(s.label)}</div>
              <h3 className="mt-1 font-title text-[22px] leading-snug text-ink">{pick(s.head)}</h3>
              <p className="mt-3 text-[15px] leading-[1.75] text-graphite text-pretty">{pick(s.body)}</p>
            </div>
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 self-start md:pt-6 text-[13px]">
              {record[s.key].map(([k, v]) => (
                <div key={k} className="contents">
                  <dt className="text-stone">{k}</dt>
                  <dd className="font-data text-ink tabular-nums">{v}</dd>
                </div>
              ))}
            </dl>
          </li>
        ))}
      </ol>
      <Link href={`/${locale}/rules/${rule.id}`} className="mt-6 inline-block text-[14px] text-ink underline underline-offset-[6px] decoration-ink/30 hover:decoration-ink">
        {zh ? `看 ${rule.id} 全文` : `Read ${rule.id}`}
      </Link>
    </div>
  );
}
