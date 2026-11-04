import Link from "next/link";
import type { Metadata } from "next";
import { locales, type Locale } from "@/lib/i18n";
import { pageMetadata } from "@/lib/seo";
import { loadVersionLabels } from "@/lib/versions";
import { DocsShell, Callout, GlanceTable } from "@/components/DocsShell";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export async function generateMetadata({ params }: { params: Promise<{ locale: string }> }): Promise<Metadata> {
  const { locale } = await params;
  return pageMetadata({
    locale,
    path: "/docs/auditor-kit",
    title: locale === "zh" ? "稽核員工具包" : "Auditor kit",
    description:
      locale === "zh"
        ? "稽核員怎麼確認一個組織真的在跑 ATR：七個問題、各要索取什麼、各怎麼驗證。"
        : "How an auditor checks that an organization really runs ATR: seven questions, what to request for each, and how to verify it.",
  });
}

type B = { en: string; zh: string };

const QUESTIONS: ReadonlyArray<{ q: B; request: B; verify: B; ev: string }> = [
  {
    q: { en: "Which version of the rules is running?", zh: "跑的是哪一版規則？" },
    request: { en: "The dependency lockfile or image manifest.", zh: "相依套件鎖定檔或映像檔清單。" },
    verify: { en: "Compare the pinned version with the npm registry and the release tag; old versions stay listed in the changelog.", zh: "把鎖定的版本對照 npm 與發布標籤；舊版本都留在版本歷程裡。" },
    ev: "EV-01",
  },
  {
    q: { en: "Which lane runs, and may it block?", zh: "跑哪個 lane？能不能阻擋？" },
    request: { en: "The deployment configuration for lane and blocking.", zh: "lane 與阻擋的部署設定。" },
    verify: { en: "Check the claim against the lane counts in rules/index.json: the enforce lane loads only maturity stable.", zh: "對照 rules/index.json 的 lane 數量：enforce lane 只載入 maturity stable。" },
    ev: "EV-02",
  },
  {
    q: { en: "Are the rules actually evaluated?", zh: "規則真的有在評估嗎？" },
    request: { en: "A sample of detection records from the period under review.", zh: "審查期間的偵測紀錄樣本。" },
    verify: { en: "In a staging environment, send one of a rule's published true-positive inputs and confirm a record names that rule ID.", zh: "在測試環境送入某條規則公開的正例輸入，確認紀錄寫出該規則 ID。" },
    ev: "EV-03",
  },
  {
    q: { en: "Do the rules behave as published?", zh: "規則行為跟公開的一致嗎？" },
    request: { en: "The self-test output for the pinned version.", zh: "鎖定版本的自測輸出。" },
    verify: { en: "Re-run the self-tests yourself on the same version; they need no network and no account.", zh: "自己在同一版本重跑自測；不需要網路，也不需要帳號。" },
    ev: "EV-04",
  },
  {
    q: { en: "Does the engine follow the specification?", zh: "引擎符合規格嗎？" },
    request: { en: "Conformance results for the engine in use.", zh: "所用引擎的符規結果。" },
    verify: { en: "Results are self-declared; re-run the suite, and check the implementer report for the engine's declaration.", zh: "結果是自我宣告；重跑套件，並在實作者報告查該引擎的宣告。" },
    ev: "EV-05",
  },
  {
    q: { en: "How accurate are the rules?", zh: "規則準確嗎？" },
    request: { en: "The measurement files the organization cites, with the lane.", zh: "組織引用的量測檔，以及對應的 lane。" },
    verify: { en: "A figure without its lane, version and caveat is not comparable. Several corpora are partly the ones rules were written from.", zh: "沒有標 lane、版本與注意事項的數字無法比較。有幾個語料部分就是撰寫規則時用的。" },
    ev: "EV-06",
  },
  {
    q: { en: "What is known not to work?", zh: "有哪些已知做不到？" },
    request: { en: "The organization's view of LIMITATIONS.md and errata for the version.", zh: "組織對該版本 LIMITATIONS.md 與勘誤的掌握。" },
    verify: { en: "Inert rules (status draft or deprecated) fire in no lane; they are not coverage.", zh: "inert 規則（status 為 draft 或 deprecated）在任何 lane 都不觸發，不能算覆蓋。" },
    ev: "EV-08",
  },
];

export default async function AuditorKitPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";
  const prefix = `/${locale}`;
  const pick = (t: B) => (zh ? t.zh : t.en);
  const versions = await loadVersionLabels();

  return (
    <DocsShell
      locale={locale}
      path="/docs/auditor-kit"
      eyebrow={zh ? "V. 證據與稽核" : "V. Evidence and audit"}
      title={zh ? "稽核員工具包" : "Auditor kit"}
      lead={
        zh
          ? "稽核員怎麼確認一個組織真的在跑 ATR，以及跑的是它聲稱的那個設定。每一步都能用公開資料自己驗，不需要找 ATR 維護者。"
          : "How an auditor checks that an organization really runs ATR, in the configuration it claims. Every step can be verified from public material, without asking the ATR maintainers."
      }
      generatedAt={versions.generatedAt}
    >
      <GlanceTable
        rows={[
          { label: zh ? "誰用" : "For", value: zh ? "內部稽核、第三方稽核、採購審查" : "Internal audit, third-party auditors, procurement review" },
          { label: zh ? "要準備" : "Inputs", value: zh ? "鎖定版本、部署設定、偵測紀錄樣本、自測與符規結果" : "Pinned version, deployment configuration, sample detection records, self-test and conformance results" },
          { label: zh ? "產出" : "Output", value: zh ? "每個問題一個結論：已驗證、部分驗證或無法驗證" : "One finding per question: verified, partly verified or not verifiable" },
          { label: zh ? "證據對照" : "Evidence", value: <Link href={`${prefix}/docs/evidence`} className="text-blue hover:underline underline-offset-4">{zh ? "證據指南 EV-01 至 EV-08" : "Evidence guide EV-01 to EV-08"}</Link> },
        ]}
      />

      <div className="mt-8">
        <Callout label={zh ? "不發證" : "No certification"}>
          {zh
            ? "ATR 不認證組織或產品，也沒有授權任何人代表 ATR 發證。這份工具包只幫稽核員驗證一個部署的說法。"
            : "ATR does not certify organizations or products, and has authorized no one to certify on its behalf. This kit only helps an auditor verify what a deployment claims."}
        </Callout>
      </div>

      <ol className="mt-12 border-t border-fog">
        {QUESTIONS.map((x, i) => (
          <li key={x.ev + i} className="py-6 border-b border-fog grid md:grid-cols-[48px_1fr] gap-3">
            <span className="font-data text-[12px] text-mist">{String(i + 1).padStart(2, "0")}</span>
            <div>
              <h2 className="text-[17px] text-ink">{pick(x.q)}</h2>
              <dl className="mt-3 grid sm:grid-cols-[110px_1fr] gap-x-4 gap-y-2 text-[13.5px] leading-[1.6]">
                <dt className="text-stone">{zh ? "索取" : "Request"}</dt>
                <dd className="text-graphite">{pick(x.request)}</dd>
                <dt className="text-stone">{zh ? "驗證" : "Verify"}</dt>
                <dd className="text-graphite">{pick(x.verify)}</dd>
                <dt className="text-stone">{zh ? "證據" : "Evidence"}</dt>
                <dd><Link href={`${prefix}/docs/evidence`} className="font-data text-[12px] text-blue hover:underline underline-offset-4">{x.ev}</Link></dd>
              </dl>
            </div>
          </li>
        ))}
      </ol>
    </DocsShell>
  );
}
