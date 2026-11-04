import type { Metadata } from "next";
import { locales, type Locale } from "@/lib/i18n";
import { pageMetadata } from "@/lib/seo";
import { loadVersionLabels } from "@/lib/versions";
import { DocsShell, Callout } from "@/components/DocsShell";

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
        ? "部署 ATR 的組織可以拿出哪些證據：設定、紀錄、測試、量測與已知限制，以及任何符規引擎怎麼產生它們。"
        : "The evidence an organization running ATR can produce: configuration, logs, tests, measurements and known limits, and how any conforming engine produces them.",
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
    shows: { en: "Which ATR release is deployed. Each rule also carries its own rule_version.", zh: "部署的是哪一版 ATR。每條規則另外帶有自己的 rule_version。" },
    produce: "npm ls agent-threat-rules",
    location: { en: "Dependency lockfile", zh: "相依套件鎖定檔" },
  },
  {
    id: "EV-02", type: "Config",
    title: { en: "Lane and blocking", zh: "Lane 與阻擋設定" },
    shows: { en: "Which maturities may fire (enforce, alert or hunt) and whether a match may block. Blocking is off unless switched on.", zh: "哪些成熟度的規則可以觸發（enforce、alert 或 hunt），以及命中時是否阻擋。阻擋預設關閉。" },
    produce: "atr guard --lane enforce --blocking   # or ATR_LANE / ATR_BLOCKING",
    location: { en: "Deployment configuration", zh: "部署設定" },
  },
  {
    id: "EV-03", type: "Logs",
    title: { en: "Detection records", zh: "偵測紀錄" },
    shows: { en: "Each match names the rule ID and severity, so a record traces back to a published rule.", zh: "每筆命中都寫明規則 ID 與嚴重度，可以追回一條公開的規則。" },
    produce: "atr scan events.json --json   # or --sarif",
    location: { en: "Logging or SIEM", zh: "日誌系統或 SIEM" },
  },
  {
    id: "EV-04", type: "Test",
    title: { en: "Rule self-tests", zh: "規則自測" },
    shows: { en: "The deployed rules still match their own true positives and stay silent on their true negatives.", zh: "部署中的規則仍然命中自己的正例，對反例不觸發。" },
    produce: "atr test rules/",
    location: { en: "CI output", zh: "CI 輸出" },
  },
  {
    id: "EV-05", type: "Test",
    title: { en: "Engine conformance", zh: "引擎符規" },
    shows: { en: "The engine evaluates rules the way the specification says. Results are self-declared and reproducible.", zh: "引擎依規格評估規則。結果為自我宣告，可重現。" },
    produce: "conformance/v1.0 runner",
    location: { en: "Conformance report", zh: "符規報告" },
  },
  {
    id: "EV-06", type: "Measurement",
    title: { en: "Published measurements", zh: "公開量測" },
    shows: { en: "Recall and false-positive figures per lane, pinned to the ATR version measured, with their caveats.", zh: "逐 lane 的召回率與誤報數字，釘住量測時的 ATR 版本，附注意事項。" },
    produce: "data/measurements/<source>/latest.json",
    location: { en: "ATR repository", zh: "ATR repository" },
  },
  {
    id: "EV-07", type: "Config",
    title: { en: "Data egress", zh: "資料外送" },
    shows: { en: "Detections stay on the machine. Sending reports anywhere needs an explicit flag and an endpoint the operator chooses; none is built in.", zh: "偵測結果留在本機。要送出報告必須明確開啟，並由營運者自行指定端點；沒有內建端點。" },
    produce: "--report-to-cloud is off by default; --tc-url is required with it",
    location: { en: "Deployment configuration", zh: "部署設定" },
  },
  {
    id: "EV-08", type: "Document",
    title: { en: "Known limits and errata", zh: "已知限制與勘誤" },
    shows: { en: "What the rules do not cover, rules that are inert, and errors found in published versions.", zh: "規則沒有涵蓋的範圍、inert 的規則，以及已發布版本中發現的錯誤。" },
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
    <DocsShell
      locale={locale}
      path="/docs/evidence"
      eyebrow={zh ? "V. 證據與稽核" : "V. Evidence and audit"}
      title={zh ? "證據指南" : "Evidence guide"}
      lead={
        zh
          ? "部署 ATR 的組織可以拿出八類證據，給內部審查、客戶問卷或第三方稽核使用。這是偵測證據，不是合規保證。"
          : "Eight kinds of evidence an organization running ATR can produce for internal review, customer questionnaires or a third-party audit. This is detection evidence, not a compliance guarantee."
      }
      generatedAt={versions.generatedAt}
    >
      <Callout label={zh ? "任何引擎" : "Any engine"}>
        {zh
          ? "指令以參考引擎（MIT，npm agent-threat-rules）為例。任何符規引擎都能用自己的方式產生同樣的證據；ATR 不指定、不推薦任何產品。"
          : "Commands use the reference engine (MIT, npm agent-threat-rules) as the example. Any conforming engine can produce the same evidence its own way; ATR does not prescribe or recommend a product."}
      </Callout>

      <div className="mt-8 overflow-x-auto">
        <table className="w-full text-left border-t border-fog min-w-[720px]">
          <thead>
            <tr className="border-b border-fog font-data text-[10px] uppercase tracking-[0.08em] text-mist">
              <th className="py-2.5 pr-4 font-normal">ID</th>
              <th className="py-2.5 pr-4 font-normal">{zh ? "證據" : "Evidence"}</th>
              <th className="py-2.5 pr-4 font-normal">{zh ? "怎麼產生（參考引擎）" : "How to produce (reference engine)"}</th>
              <th className="py-2.5 font-normal">{zh ? "典型位置" : "Typical location"}</th>
            </tr>
          </thead>
          <tbody>
            {EVIDENCE.map((e) => (
              <tr key={e.id} className="border-b border-fog align-top">
                <td className="py-4 pr-4 whitespace-nowrap">
                  <div className="font-data text-[11.5px] text-ink">{e.id}</div>
                  <div className="mt-1 font-data text-[10px] uppercase tracking-[0.06em] text-mist">{e.type}</div>
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
  );
}
