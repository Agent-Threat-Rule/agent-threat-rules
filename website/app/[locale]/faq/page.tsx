import Link from "next/link";
import type { Metadata } from "next";
import type { ReactNode } from "react";
import { locales, type Locale } from "@/lib/i18n";
import { pageMetadata } from "@/lib/seo";
import { loadVersionLabels } from "@/lib/versions";
import { loadSiteStats } from "@/lib/stats";
import { CONTACTS, REPO_URL } from "@/lib/legal";
import { DocsShell } from "@/components/DocsShell";
import Phrased from "@/components/Phrased";

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
        ? <>AI 代理威脅的開放偵測規則標準。內容有一份<Link href={`${p}/spec`} className={a}>規格</Link>、一組有版本的 YAML 規則，還有一套測試，任何引擎都能拿來證明自己符合規格。</>
        : <>An open detection-rule standard for AI agent threats: a <Link href={`${p}/spec`} className={a}>specification</Link>, a versioned set of YAML rules, and a test suite any engine can use to show it conforms.</>,
    },
    {
      q: zh ? "要錢嗎？" : "Does it cost anything?",
      a: zh
        ? <>不用錢。規則和規格都是 MIT 授權，誰都能使用、實作、修改。機構會員還沒開放。會員也買不到任何規則的結果。</>
        : <>No. The rules and the specification are MIT licensed, so anyone may use, implement and modify them. Organization membership is not open yet. It never buys the outcome of a rule.</>,
    },
    {
      q: zh ? "誰在維護？" : "Who maintains it?",
      a: zh
        ? <>現在是過渡期，由維護者管理。技術指導委員會（TSC）正在籌組。詳見<Link href={`${p}/governance`} className={a}>治理</Link>與<Link href={`${p}/charter`} className={a}>章程</Link>。</>
        : <>The maintainers, for now. This is a transition period while the Technical Steering Committee is being seated. See <Link href={`${p}/governance`} className={a}>governance</Link> and the <Link href={`${p}/charter`} className={a}>charter</Link>.</>,
    },
    {
      q: zh ? "ATR 會認證產品或組織嗎？" : "Does ATR certify products or organizations?",
      a: zh
        ? <>不會。ATR 不稽核，也不認證組織或它們的部署。引擎符不符合規格，是對照公開的<Link href={`${p}/conformance`} className={a}>測試套件</Link>自我宣告，也就是 L1 符規自我宣告，不是 ATR 發的認證，和會員資格也無關。稽核員可以用<Link href={`${p}/docs/auditor-kit`} className={a}>稽核員工具包</Link>自己驗證。</>
        : <>No. ATR does not audit or certify organizations or their deployments. Engines self-declare conformance against the public <Link href={`${p}/conformance`} className={a}>test suite</Link>. That is a self-declared L1 conformance, not a certification issued by ATR, and it has nothing to do with membership. Auditors can verify a deployment themselves with the <Link href={`${p}/docs/auditor-kit`} className={a}>auditor kit</Link>.</>,
    },
    {
      q: zh ? "lane 是什麼？" : "What is a lane?",
      a: zh
        ? <>lane 決定哪些成熟度的規則可以觸發。enforce 只跑 maturity 為 stable 的規則，要開阻擋就用這條。alert 跑 stable 和 test。hunt 跑全部生效的規則，也是預設。引擎和 Claude Code hook 的阻擋預設是關的；Mastra、OpenShell、NemoClaw 轉接器則預設會擋 high 和 critical 的命中。</>
        : <>A lane decides which rule maturities may fire. Enforce runs maturity stable only, and it is the lane to run with blocking on. Alert runs stable and test. Hunt runs every effective rule and is the default. Blocking is off by default in the engine and the Claude Code hook; the Mastra, OpenShell and NemoClaw adapters block high and critical matches by default.</>,
    },
    {
      q: zh ? "為什麼有三個規則數？" : "Why are there three rule counts?",
      a: zh
        ? <>main 上有 {stats.ruleFileCount} 個規則檔。其中 {stats.ruleCount} 條生效，也就是至少有一個 lane 會載入。{stats.ruleInertCount} 條是 inert，status 為 draft 或 deprecated，任何 lane 都不載入。只講一個數字，不是多報就是少報，所以全站每個數字都標明算的是什麼。</>
        : <>There are {stats.ruleFileCount} rule files on main. {stats.ruleCount} are effective, meaning at least one lane loads them. {stats.ruleInertCount} are inert: their status is draft or deprecated, and no lane loads them. Any one number alone overstates or understates, so every figure on this site says what it counts.</>,
    },
    {
      q: zh ? "要引用哪個版本？" : "Which version should I cite?",
      a: zh
        ? <>引用規格就用規格版本，引用軟體就用 npm 版本。兩個版本分開標示，格式見<Link href={`${p}/citations`} className={a}>引用</Link>頁面。</>
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
        ? <>參考引擎在你自己的程序裡評估規則。回報到外部服務預設是關的，也沒有內建的接收端點。要打開，必須明確設定，並且自己指定接收方。</>
        : <>The reference engine evaluates rules inside your own process. Reporting to an outside service is off by default and has no built-in endpoint. Turning it on takes an explicit flag and a receiver you choose.</>,
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
        ? <>入會暫停受理，隱私說明定稿後開放。開放後加入免費，名錄只列本人同意公開的人。</>
        : <>Joining is paused until the privacy notice is final. Once it opens, joining is free, and the directory lists only people who agreed to be listed.</>,
    },
  ];

  return (
    <Phrased>
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
    </Phrased>
  );
}
