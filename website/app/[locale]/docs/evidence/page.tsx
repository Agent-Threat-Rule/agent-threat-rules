import type { Metadata } from "next";
import { locales, type Locale } from "@/lib/i18n";
import { pageMetadata } from "@/lib/seo";
import { loadVersionLabels } from "@/lib/versions";
import { DocsShell, Callout } from "@/components/DocsShell";
import Phrased from "@/components/Phrased";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export async function generateMetadata({ params }: { params: Promise<{ locale: string }> }): Promise<Metadata> {
  const { locale } = await params;
  return pageMetadata({
    locale,
    path: "/docs/evidence",
    title: locale === "zh" ? "證據指南" : "Evidence guide",
    description:
      locale === "zh"
        ? "跑 ATR 的組織能拿出哪些證據：設定、紀錄、測試、量測、已知限制，以及任何符規引擎怎麼產生它們。"
        : "What an organization running ATR can show: configuration, logs, tests, measurements and known limits. Also how any conforming engine produces each one.",
  });
}

type B = { en: string; zh: string };

interface Evidence {
  id: string;
  type: "Config" | "Logs" | "Test" | "Measurement" | "Document";
  title: B;
  shows: B;
  produce: string;
  location: B;
}

// Commands are the reference engine's (MIT, npm agent-threat-rules). Any
// conforming engine can produce the same evidence with its own commands.
const EVIDENCE: ReadonlyArray<Evidence> = [
  {
    id: "EV-01", type: "Config",
    title: { en: "Rule set and version", zh: "規則集與版本" },
    shows: { en: "Which ATR release is deployed. Each rule also carries its own rule_version.", zh: "部署的是哪一版 ATR。每條規則還有自己的 rule_version。" },
    produce: "npm ls agent-threat-rules",
    location: { en: "Dependency lockfile", zh: "相依套件鎖定檔" },
  },
  {
    id: "EV-02", type: "Config",
    title: { en: "Lane and blocking", zh: "lane 與阻擋設定" },
    shows: { en: "The lane, enforce, alert or hunt, decides which maturities may fire. The setting also says whether a match may block. Blocking is off until someone turns it on.", zh: "lane 決定哪些成熟度的規則可以觸發，分 enforce、alert、hunt。設定裡也寫了命中時要不要阻擋。阻擋預設是關的。" },
    produce: "atr guard --lane enforce --blocking   # or ATR_LANE / ATR_BLOCKING",
    location: { en: "Deployment configuration", zh: "部署設定" },
  },
  {
    id: "EV-03", type: "Logs",
    title: { en: "Detection records", zh: "偵測紀錄" },
    shows: { en: "Each match names the rule ID and severity, so a record traces back to a published rule.", zh: "每筆命中都寫著規則 ID 和嚴重度，追得回一條公開的規則。" },
    produce: "atr scan events.json --json   # or --sarif",
    location: { en: "Logging or SIEM", zh: "日誌系統或 SIEM" },
  },
  {
    id: "EV-04", type: "Test",
    title: { en: "Rule self-tests", zh: "規則自測" },
    shows: { en: "The deployed rules still match their own true positives and stay silent on their true negatives.", zh: "部署中的規則，仍然會命中自己的正例，碰到反例也不會觸發。" },
    produce: "atr test rules/",
    location: { en: "CI output", zh: "CI 輸出" },
  },
  {
    id: "EV-05", type: "Test",
    title: { en: "Engine conformance", zh: "引擎符規" },
    shows: { en: "The engine evaluates rules the way the specification says. Results are self-declared and reproducible.", zh: "引擎照規格評估規則。結果是自我宣告的，可以重現。" },
    produce: "conformance/v1.0 runner",
    location: { en: "Conformance report", zh: "符規報告" },
  },
  {
    id: "EV-06", type: "Measurement",
    title: { en: "Published measurements", zh: "公開量測" },
    shows: { en: "Recall and false-positive figures for each lane, tied to the ATR version that was measured, with their caveats.", zh: "每個 lane 的召回率和誤報數字，綁定量測時的 ATR 版本，附上注意事項。" },
    produce: "data/measurements/<source>/latest.json",
    location: { en: "ATR repository", zh: "ATR repository" },
  },
  {
    id: "EV-07", type: "Config",
    title: { en: "Data egress", zh: "資料外送" },
    shows: { en: "Detections stay on the machine. Sending a report anywhere takes an explicit flag and an endpoint the operator picks. None is built in.", zh: "偵測結果留在本機。要把報告送出去，得明確打開，端點也由營運者自己指定。沒有內建端點。" },
    produce: "--report-to-cloud is off by default; --tc-url is required with it",
    location: { en: "Deployment configuration", zh: "部署設定" },
  },
  {
    id: "EV-08", type: "Document",
    title: { en: "Known limits and errata", zh: "已知限制與勘誤" },
    shows: { en: "What the rules do not cover, which rules are inert, and errors found in published versions.", zh: "規則沒涵蓋的範圍、不生效的規則，還有已發布版本裡找到的錯誤。" },
    produce: "LIMITATIONS.md · /errata · rules/index.json (lanes)",
    location: { en: "ATR repository and site", zh: "ATR repository 與網站" },
  },
];

export default async function EvidencePage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";
  const pick = (t: B) => (zh ? t.zh : t.en);
  const versions = await loadVersionLabels();

  return (
    <Phrased>
    <DocsShell
      locale={locale}
      path="/docs/evidence"
      eyebrow={zh ? "V. 證據與稽核" : "V. Evidence and audit"}
      title={zh ? "證據指南" : "Evidence guide"}
      lead={
        zh
          ? "跑 ATR 的組織可以拿出八類證據，用在內部審查、客戶問卷或第三方稽核。這些是偵測的證據，不是合規保證。"
          : "An organization running ATR can produce eight kinds of evidence, for internal review, customer questionnaires or a third-party audit. This is evidence of detection. It is not a compliance guarantee."
      }
      generatedAt={versions.generatedAt}
    >
      <Callout label={zh ? "任何引擎" : "Any engine"}>
        {zh
          ? "指令以參考引擎為例，也就是 npm 上 MIT 授權的 agent-threat-rules。任何符規引擎都能用自己的方式產生同樣的證據。ATR 不指定、也不推薦任何產品。"
          : "The commands use the reference engine, the MIT-licensed agent-threat-rules package on npm. Any conforming engine can produce the same evidence its own way. ATR does not prescribe or recommend a product."}
      </Callout>

      <div className="mt-8 overflow-x-auto">
        <table className="w-full text-left border-t border-fog min-w-[720px]">
          <thead>
            <tr className="border-b border-fog font-data text-[10px] uppercase tracking-[0.08em] text-mist">
              <th className="py-2.5 pr-4 font-normal">ID</th>
              <th className="py-2.5 pr-4 font-normal">{zh ? "證據" : "Evidence"}</th>
              <th className="py-2.5 pr-4 font-normal">{zh ? "參考引擎的指令" : "Reference engine command"}</th>
              <th className="py-2.5 font-normal">{zh ? "通常放在" : "Usually kept in"}</th>
            </tr>
          </thead>
          <tbody>
            {EVIDENCE.map((e) => (
              <tr key={e.id} className="border-b border-fog align-top">
                <td className="py-4 pr-4 whitespace-nowrap">
                  <div className="font-data text-[11.5px] text-ink">{e.id}</div>
                  <div className="text-[13px] text-stone mt-1">{e.type}</div>
                </td>
                <td className="py-4 pr-4">
                  <div className="text-[14px] text-ink">{pick(e.title)}</div>
                  <p className="mt-1 text-[12.5px] leading-[1.6] text-stone">{pick(e.shows)}</p>
                </td>
                <td className="py-4 pr-4"><code className="font-data text-[11.5px] text-graphite bg-ash px-1.5 py-0.5 rounded-[2px] break-words">{e.produce}</code></td>
                <td className="py-4 text-[12.5px] text-graphite">{pick(e.location)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </DocsShell>
    </Phrased>
  );
}
