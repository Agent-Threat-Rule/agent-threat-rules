import Link from "next/link";
import type { Metadata } from "next";
import { locales, type Locale } from "@/lib/i18n";
import { pageMetadata } from "@/lib/seo";
import { loadVersionLabels } from "@/lib/versions";
import { DocsShell, Callout, GlanceTable } from "@/components/DocsShell";
import Phrased from "@/components/Phrased";

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
        ? "稽核員怎麼確認一個組織真的在跑 ATR：八個問題，每題要索取什麼、怎麼驗。"
        : "How an auditor checks that an organization really runs ATR: eight questions, what to ask for on each, and how to verify it.",
  });
}

type B = { en: string; zh: string };

const QUESTIONS: ReadonlyArray<{ q: B; request: B; verify: B; ev: string }> = [
  {
    q: { en: "Which version of the rules is running?", zh: "跑的是哪一版規則？" },
    request: { en: "The dependency lockfile or image manifest.", zh: "相依套件鎖定檔或映像檔清單。" },
    verify: { en: "Compare the pinned version with the npm registry and the release tag. Old versions stay listed in the changelog.", zh: "把鎖定的版本拿去對 npm 和發布標籤。舊版本都還列在版本歷程裡。" },
    ev: "EV-01",
  },
  {
    q: { en: "Which lane runs, and may it block?", zh: "跑哪個 lane？能不能阻擋？" },
    request: { en: "The deployment configuration for lane and blocking.", zh: "lane 和阻擋的部署設定。" },
    verify: { en: "Check the claim against the lane counts in rules/index.json. The enforce lane loads only stable rules.", zh: "拿 rules/index.json 的 lane 數量來對。enforce lane 只載入 stable 的規則。" },
    ev: "EV-02",
  },
  {
    q: { en: "Are the rules actually evaluated?", zh: "規則真的有在評估嗎？" },
    request: { en: "A sample of detection records from the period under review.", zh: "審查期間的偵測紀錄樣本。" },
    verify: { en: "In a staging environment, send one of a rule's published true-positive inputs. Confirm that a record names the rule ID.", zh: "在測試環境送入某條規則公開的正例輸入，看紀錄有沒有寫出那條規則的 ID。" },
    ev: "EV-03",
  },
  {
    q: { en: "Do the rules behave as published?", zh: "規則的行為，跟公開的一樣嗎？" },
    request: { en: "The self-test output for the pinned version.", zh: "鎖定版本的自測輸出。" },
    verify: { en: "Re-run the self-tests yourself on the same version. They need no network and no account.", zh: "在同一版本上自己重跑自測。不用網路，也不用帳號。" },
    ev: "EV-04",
  },
  {
    q: { en: "Does the engine follow the specification?", zh: "引擎符合規格嗎？" },
    request: { en: "Conformance results for the engine in use.", zh: "正在用的引擎的符規結果。" },
    verify: { en: "Results are self-declared. Re-run the suite, then look up the engine's declaration in the implementer report.", zh: "結果是自我宣告的。自己重跑一次套件，再到實作者報告裡找這個引擎的宣告。" },
    ev: "EV-05",
  },
  {
    q: { en: "How accurate are the rules?", zh: "規則準確嗎？" },
    request: { en: "The measurement files the organization cites, with the lane.", zh: "組織引用的量測檔，和對應的 lane。" },
    verify: { en: "A figure without its lane, version and caveat can't be compared. Several corpora are partly the same ones the rules were written from.", zh: "沒標 lane、版本和注意事項的數字，沒辦法比較。有幾個語料，其中一部分就是寫規則時用的。" },
    ev: "EV-06",
  },
  {
    q: { en: "Does detection data leave the machine?", zh: "偵測資料會不會送出去？" },
    request: { en: "The deployment configuration and command lines, including any --report-to-cloud, --tc-url or ATR_TC_URL setting.", zh: "部署設定和執行指令，包括有沒有設 --report-to-cloud、--tc-url 或 ATR_TC_URL。" },
    verify: { en: "Reporting is off by default. Turning it on with --report-to-cloud requires an endpoint set with --tc-url or ATR_TC_URL, because ATR builds none in. If either is set, record which endpoint the reports go to and who runs it. The --semantic option also sends input text to the judge API the operator configures; if it is on, record that endpoint too.", zh: "回報預設是關的。用 --report-to-cloud 打開時，一定要用 --tc-url 或 ATR_TC_URL 指定端點，ATR 沒有內建端點。只要有設，就記下報告送到哪個端點、由誰營運。另外，--semantic 選項會把輸入內容送到營運者設定的 judge API；有開的話，那個端點也要記下。" },
    ev: "EV-07",
  },
  {
    q: { en: "What is known not to work?", zh: "有哪些已知做不到？" },
    request: { en: "What the organization knows of LIMITATIONS.md and the errata for that version.", zh: "組織對這一版的 LIMITATIONS.md 和勘誤掌握多少。" },
    verify: { en: "Inert rules are draft or deprecated and fire in no lane. They do not count as coverage.", zh: "不生效的規則是 draft 或 deprecated，在哪個 lane 都不會觸發，不能算進覆蓋範圍。" },
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
    <Phrased>
    <DocsShell
      locale={locale}
      path="/docs/auditor-kit"
      eyebrow={zh ? "V. 證據與稽核" : "V. Evidence and audit"}
      title={zh ? "稽核員工具包" : "Auditor kit"}
      lead={
        zh
          ? "稽核員怎麼確認一個組織真的在跑 ATR，跑的也是它說的那個設定。每一步都能拿公開資料自己驗，不必找 ATR 維護者。"
          : "How an auditor checks that an organization really runs ATR, in the configuration it claims. Every step can be checked against public material. There is no need to ask the ATR maintainers."
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
        <Callout label={zh ? "ATR 不做稽核" : "No audits by ATR"}>
          {zh
            ? "ATR 不稽核、也不認證任何組織或部署，也沒有授權任何人代表 ATR 做這件事。引擎符不符規，是對照公開測試套件自我宣告的。這份工具包只幫稽核員驗證一個部署的說法。"
            : "ATR does not audit or certify organizations or their deployments. It has authorized no one to do so on its behalf. Engine conformance is self-declared against the public test suite. This kit only helps an auditor check what one deployment claims."}
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
    </Phrased>
  );
}
