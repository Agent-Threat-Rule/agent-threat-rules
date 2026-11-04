import Link from "next/link";
import type { Metadata } from "next";
import type { ReactNode } from "react";
import { locales, type Locale } from "@/lib/i18n";
import { pageMetadata } from "@/lib/seo";
import { loadVersionLabels } from "@/lib/versions";
import { loadSiteStats } from "@/lib/stats";
import { CONTACTS, REPO_URL } from "@/lib/legal";
import { DocsShell } from "@/components/DocsShell";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export async function generateMetadata({ params }: { params: Promise<{ locale: string }> }): Promise<Metadata> {
  const { locale } = await params;
  return pageMetadata({
    locale,
    path: "/faq",
    title: locale === "zh" ? "常見問題" : "Frequently asked questions",
    description:
      locale === "zh"
        ? "ATR 是什麼、要不要錢、誰維護、認不認證、lane 與規則數怎麼算、怎麼回報問題。"
        : "What ATR is, what it costs, who maintains it, what it certifies, how lanes and rule counts work, and how to report a problem.",
  });
}

const a = "text-blue hover:underline underline-offset-4";

export default async function FaqPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";
  const p = `/${locale}`;
  const versions = await loadVersionLabels();
  const stats = loadSiteStats();

  const items: ReadonlyArray<{ q: string; a: ReactNode }> = [
    {
      q: zh ? "ATR 是什麼？" : "What is ATR?",
      a: zh
        ? <>AI 代理威脅的開放偵測規則標準：一份<Link href={`${p}/spec`} className={a}>規格</Link>、一組版本化的 YAML 規則，以及讓任何引擎證明自己符合規格的測試套件。</>
        : <>An open detection-rule standard for AI agent threats: a <Link href={`${p}/spec`} className={a}>specification</Link>, a versioned set of YAML rules, and a test suite any engine can use to show it conforms.</>,
    },
    {
      q: zh ? "要錢嗎？" : "Does it cost anything?",
      a: zh
        ? <>不用。規則與規格以 MIT 授權，任何人都能使用、實作、修改。<Link href={`${p}/community/membership`} className={a}>機構會員</Link>是選擇性的，而且尚未開放；會員買不到任何規則的結果。</>
        : <>No. The rules and the specification are MIT licensed: anyone may use, implement and modify them. <Link href={`${p}/community/membership`} className={a}>Organization membership</Link> is optional and not yet open, and it never buys the outcome of a rule.</>,
    },
    {
      q: zh ? "誰在維護？" : "Who maintains it?",
      a: zh
        ? <>目前由維護者在過渡期管理，技術指導委員會（TSC）正在籌組。見<Link href={`${p}/governance`} className={a}>治理</Link>與<Link href={`${p}/charter`} className={a}>章程</Link>。</>
        : <>Maintainers, during a transition while the Technical Steering Committee is being seated. See <Link href={`${p}/governance`} className={a}>governance</Link> and the <Link href={`${p}/charter`} className={a}>charter</Link>.</>,
    },
    {
      q: zh ? "ATR 會認證產品或組織嗎？" : "Does ATR certify products or organizations?",
      a: zh
        ? <>ATR 不稽核、不認證組織或它們的部署。引擎的符規是依公開<Link href={`${p}/conformance`} className={a}>測試套件</Link>自我宣告；ATR-Certified 標示依測試結果判定，與會員資格無關。稽核員可以用<Link href={`${p}/docs/auditor-kit`} className={a}>稽核員工具包</Link>自行驗證。</>
        : <>ATR does not audit or certify organizations or their deployments. Engine conformance is self-declared against the public <Link href={`${p}/conformance`} className={a}>test suite</Link>; the ATR-Certified designation follows those results and never membership. Auditors can verify a deployment with the <Link href={`${p}/docs/auditor-kit`} className={a}>auditor kit</Link>.</>,
    },
    {
      q: zh ? "lane 是什麼？" : "What is a lane?",
      a: zh
        ? <>lane 決定哪些成熟度的規則會觸發。enforce 只跑 maturity stable（可以開阻擋）；alert 跑 stable 與 test；hunt 跑全部生效規則，是預設。阻擋預設關閉。</>
        : <>A lane decides which rule maturities may fire. Enforce runs maturity stable only (the lane to run with blocking on); alert runs stable and test; hunt runs every effective rule and is the default. Blocking is off by default.</>,
    },
    {
      q: zh ? "為什麼有三個規則數？" : "Why are there three rule counts?",
      a: zh
        ? <>main 上有 {stats.ruleFileCount} 個規則檔，其中 {stats.ruleCount} 條生效（至少一個 lane 會載入），{stats.ruleInertCount} 條 inert（status 為 draft 或 deprecated，任何 lane 都不載入）。只引用一個數字會多報或少報，所以全站都標口徑。</>
        : <>There are {stats.ruleFileCount} rule files on main: {stats.ruleCount} are effective (loaded by at least one lane) and {stats.ruleInertCount} are inert (status draft or deprecated; no lane loads them). Quoting one number alone overstates or understates, so every figure on this site says what it counts.</>,
    },
    {
      q: zh ? "要引用哪個版本？" : "Which version should I cite?",
      a: zh
        ? <>引用規格時用規格版本；引用軟體時用 npm 版本。兩者分開標示，格式見<Link href={`${p}/citations`} className={a}>引用</Link>。</>
        : <>Cite the specification version for the specification, and the npm version for the software. They are labelled apart; formats are on the <Link href={`${p}/citations`} className={a}>citation page</Link>.</>,
    },
    {
      q: zh ? "ATR 跟 OWASP、MITRE 有關係嗎？" : "Is ATR affiliated with OWASP or MITRE?",
      a: zh
        ? <>沒有隸屬關係。<Link href={`${p}/docs/crosswalks`} className={a}>框架對照</Link>是 ATR 自己寫的文件，框架方沒有審查或背書。</>
        : <>No. The <Link href={`${p}/docs/crosswalks`} className={a}>crosswalks</Link> are ATR&apos;s own documents; the framework owners have not reviewed or endorsed them.</>,
    },
    {
      q: zh ? "ATR 會把我的資料送出去嗎？" : "Does ATR send my data anywhere?",
      a: zh
        ? <>參考引擎在你的程序內評估規則。回報到外部服務預設關閉，而且沒有內建端點；要開啟，必須明確設定，並自行指定接收方。</>
        : <>The reference engine evaluates rules in your process. Reporting to an outside service is off by default and has no built-in endpoint; turning it on needs an explicit flag and a receiver you choose.</>,
    },
    {
      q: zh ? "發現安全漏洞怎麼回報？" : "How do I report a security vulnerability?",
      a: zh
        ? <>請私下回報：用 GitHub 的 private vulnerability reporting，或寫信到 {CONTACTS.security}。不要開公開 issue。流程見 <a href={`${REPO_URL}/blob/main/SECURITY.md`} className={a}>SECURITY.md</a>。</>
        : <>Privately: through GitHub private vulnerability reporting, or by email to {CONTACTS.security}. Do not open a public issue. The process is in <a href={`${REPO_URL}/blob/main/SECURITY.md`} className={a}>SECURITY.md</a>.</>,
    },
    {
      q: zh ? "誤判或繞過怎麼回報？" : "How do I report a false positive or a bypass?",
      a: zh
        ? <>用 GitHub 的 <a href={`${REPO_URL}/issues/new?template=false-positive.yml`} className={a}>誤判表單</a>或<a href={`${REPO_URL}/issues/new?template=evasion-report.yml`} className={a}>繞過表單</a>。被採納的回報會在版本說明裡列名。</>
        : <>With the GitHub <a href={`${REPO_URL}/issues/new?template=false-positive.yml`} className={a}>false-positive form</a> or the <a href={`${REPO_URL}/issues/new?template=evasion-report.yml`} className={a}>evasion form</a>. Accepted reports are credited in the release notes.</>,
    },
    {
      q: zh ? "怎麼加入？" : "How do I join?",
      a: zh
        ? <>見<Link href={`${p}/community/join`} className={a}>加入社群</Link>。加入免費，名錄只列本人同意公開的人。</>
        : <>See <Link href={`${p}/community/join`} className={a}>join the community</Link>. Joining is free, and the directory lists only people who agreed to be listed.</>,
    },
  ];

  return (
    <DocsShell
      locale={locale}
      path="/faq"
      eyebrow={zh ? "VIII. 說明與法律" : "VIII. Help and legal"}
      title={zh ? "常見問題" : "Frequently asked questions"}
      generatedAt={versions.generatedAt}
    >
      <dl className="border-t border-fog">
        {items.map((it, i) => (
          <div key={it.q} className="py-6 border-b border-fog grid md:grid-cols-[48px_1fr] gap-3">
            <span className="font-data text-[12px] text-mist">{String(i + 1).padStart(2, "0")}</span>
            <div>
              <dt className="text-[17px] text-ink">{it.q}</dt>
              <dd className="mt-2 text-[14.5px] leading-[1.7] text-graphite max-w-[700px]">{it.a}</dd>
            </div>
          </div>
        ))}
      </dl>
    </DocsShell>
  );
}
