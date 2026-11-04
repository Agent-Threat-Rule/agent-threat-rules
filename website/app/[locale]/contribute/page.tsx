import { Reveal } from "@/components/Reveal";
import { locales, t, type Locale } from "@/lib/i18n";
import type { Metadata } from "next";
import { pageMetadata } from "@/lib/seo";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string }>;
}): Promise<Metadata> {
  const { locale } = await params;
  return pageMetadata({
    locale,
    path: "/contribute",
    title: "Contribute",
    description: "Four ways to contribute to ATR: report evasions, report false positives, submit rules, or write rules with an AI assistant.",
  });
}

export default async function ContributePage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";

  return (
    <div className="pt-20 pb-16 px-6 max-w-[1120px] mx-auto">
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {t(locale, "contribute.label")}
        </div>
      </Reveal>
      <Reveal delay={0.1}>
        <h1 className="text-[32px] md:text-[44px] leading-[1.12] tracking-[-0.03em] font-medium mb-2 max-w-[600px]">
          {zh
            ? "你找到的攻擊，可以變成所有人的規則。"
            : "The attack you found can become everyone's rule."}
        </h1>
      </Reveal>
      <Reveal delay={0.2}>
        <p className="text-base text-stone font-light mb-10 max-w-[560px]">
          {zh
            ? "ATR 是公共財。任何人都能提規則，通過公開的 PR 和安全閘，它就成為全世界防守者共用標準的一部分。MIT 授權，不需要專屬工具，也不用簽 CLA。從回報一個繞過手法開始，15 分鐘。"
            : "ATR is a public good. Anyone can propose a rule. Once it clears a public PR and the safety gate, it is part of a standard every defender shares. MIT licensed, with no proprietary tooling and no CLA. Start by reporting an evasion. It takes fifteen minutes."}
        </p>
      </Reveal>

      {/* ── Integrating ATR into your project (top — most asked path) ── */}
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {zh ? "把 ATR 接到你的專案" : "Integrating ATR into your project"}
        </div>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="border border-fog mb-12 grid grid-cols-1 md:grid-cols-2">
          <div className="p-6 md:p-7 border-b md:border-b-0 md:border-r border-fog">
            <div className="font-data text-[11px] text-stone tracking-wide uppercase mb-2">
              {zh ? "規劃中 / 實作中" : "Planning or implementing"}
            </div>
            <h3 className="font-display text-base font-semibold text-ink mb-2">
              {zh ? "開一個 Integration Request issue" : "Open an Integration Request issue"}
            </h3>
            <p className="text-sm text-stone leading-relaxed mb-3">
              {zh
                ? "任何引擎都可以實作這個標準，這條路是給正在實作的人。表單是結構化的，5 分鐘填完。需要 spec 導讀、設計審查、你那個語言的範例程式碼，或合規框架對照，就走這條。維護者七天內回覆。"
                : "Any engine may implement the standard. This path is for the people building one. The intake form is structured and takes five minutes. Use it when you need a spec walkthrough, a design review, sample code for your language, or a mapping to compliance frameworks. Maintainers respond within seven days."}
            </p>
            <a
              href="https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new?template=integration-request.yml"
              target="_blank"
              rel="noopener noreferrer"
              className="font-data text-xs text-blue hover:underline"
            >
              {zh ? "開 issue" : "Open the issue"} &rarr;
            </a>
          </div>
          <div className="p-6 md:p-7">
            <div className="font-data text-[11px] text-stone tracking-wide uppercase mb-2">
              {zh ? "已經上線" : "Already shipped"}
            </div>
            <h3 className="font-display text-base font-semibold text-ink mb-2">
              {zh ? "提 PR 加進 ADOPTERS.md" : "Open a PR against ADOPTERS.md"}
            </h3>
            <p className="text-sm text-stone leading-relaxed mb-3">
              {zh
                ? "整合已經公開、可以驗證，就走這條。格式符合 schema、附上證據連結，就會合併。維護者不預先審核採用者，做法跟 Sigma 一樣。"
                : "Take this path once your integration is public and verifiable. Entries that match the schema and carry a verifiable evidence link get merged. Maintainers do not pre-approve adopters. Sigma works the same way."}
            </p>
            <a
              href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/ADOPTERS.md"
              target="_blank"
              rel="noopener noreferrer"
              className="font-data text-xs text-blue hover:underline"
            >
              ADOPTERS.md &rarr;
            </a>
          </div>
        </div>
      </Reveal>

      {/* ── Quick Actions (the most important part) ── */}
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {zh ? "改進規則本身" : "Improve the rules themselves"}
        </div>
      </Reveal>
      <Reveal delay={0.3}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-12">
          {[
            {
              title: zh ? "提交新規則（5 分鐘，不用 fork）" : "Submit a new rule (5 min, no fork)",
              desc: zh
                ? "發現新的攻擊手法？填一個 issue，bot 會自動把它轉成 draft proposal PR。不用 clone repo，也不用寫 YAML。"
                : "Found a new attack pattern? File one issue and a bot turns it into a draft proposal PR. No clone, no YAML.",
              time: "~5 min",
              href: "https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new?template=new-rule.yml",
              cta: zh ? "開一個 issue" : "Open an issue",
            },
            {
              title: zh ? "提交紅隊 probe（納入 benchmark）" : "Submit a red-team probe (joins the benchmark)",
              desc: zh
                ? "手上有攻擊 payload，也有長得像但無害的對照樣本？維護者審過後會轉成提案。合併之後，你的 probe 會自動納入下一輪 benchmark。recall 數字裡看得到你的貢獻。"
                : "Have an attack payload and benign look-alikes? A maintainer reviews it and turns it into a proposal. Once merged, your probe joins the next benchmark run, and your work shows up in the recall numbers.",
              time: "~10 min",
              href: "https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new?template=red-team-probe.yml",
              cta: zh ? "送一個 probe" : "Submit a probe",
            },
            {
              title: zh ? "回報繞過手法" : "Report an evasion",
              desc: zh
                ? "找到繞過規則的方法？每一個確認過的繞過，都會讓規則被改進。這是影響最大的一種貢獻。"
                : "Found a way past a rule? Every confirmed evasion leads to a rule fix. This is the most impactful kind of contribution.",
              time: "~15 min",
              href: "https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new?template=evasion-report.yml",
              cta: zh ? "開一個 issue" : "Open an issue",
            },
            {
              title: zh ? "回報誤判" : "Report a false positive",
              desc: zh
                ? "規則把正常內容當成攻擊？每一筆誤判回報，都讓 ATR 公布的逐車道精確度更接近真實。一個標準的可信度，來自它肯公開自己最差的數字。"
                : "A rule fired on legitimate content? Every false-positive report sharpens the per-lane precision ATR publishes. A standard earns trust by publishing its worst figure, not hiding it.",
              time: "~20 min",
              href: "https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new?template=false-positive.yml",
              cta: zh ? "開一個 issue" : "Open an issue",
            },
            {
              title: zh ? "自己寫完整規則（進階）" : "Write a full rule (advanced)",
              desc: zh
                ? "想直接寫 YAML？fork repo，照著 spec 寫，跑 atr validate 和 atr test，再提 PR。教學會一步一步帶你。"
                : "Want to write the YAML yourself? Fork the repo, follow the spec, run atr validate and atr test, then open a PR. The guide walks through every step.",
              time: "1-2 hr",
              href: "https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/examples/how-to-write-a-rule.md",
              cta: zh ? "看教學" : "See the guide",
            },
            {
              title: zh ? "讓 AI 幫你寫" : "Contribute with an AI assistant",
              desc: zh
                ? "用 Claude Code 或 Cursor 接上 ATR 的 MCP server。AI 寫 YAML，你來審。"
                : "Use Claude Code or Cursor with ATR's MCP server. The AI writes the YAML, and you review it.",
              time: zh ? "不一定" : "Varies",
              href: "https://github.com/Agent-Threat-Rule/agent-threat-rules#mcp-server",
              cta: zh ? "看 MCP 設定" : "See the MCP setup",
            },
          ].map((item, i) => (
            <Reveal key={item.title} delay={0.1 * i}>
              <div className="border border-fog p-6 h-full flex flex-col">
                <div className="flex items-start justify-between gap-3 mb-3">
                  <h2 className="font-display text-base font-semibold text-ink">{item.title}</h2>
                  <span className="font-data text-xs text-stone whitespace-nowrap mt-0.5">{item.time}</span>
                </div>
                <p className="text-sm text-stone leading-[1.6] mb-4 flex-1">{item.desc}</p>
                <a
                  href={item.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-data text-sm text-blue hover:underline"
                >
                  {item.cta} &rarr;
                </a>
              </div>
            </Reveal>
          ))}
        </div>
      </Reveal>

      {/* ── What happens after you contribute (sets motivation) ── */}
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {zh ? "送出後會發生什麼" : "What happens after you contribute"}
        </div>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="border border-fog p-6 mb-12">
          <ol className="text-sm text-stone leading-[1.7] space-y-2 list-decimal list-inside marker:font-data marker:text-ink">
            <li>
              {zh
                ? "新規則 issue：bot 會把你的 issue 轉成 proposals/ 底下的 YAML 草案，開一個 draft PR，author 欄位寫的是你的名字。上面其他類型的 issue，包括紅隊 probe，會先由維護者審。維護者接受之後，才會有 PR。"
                : "New-rule issues: a bot converts your issue into a YAML draft under proposals/ and opens a draft PR with your name in the author field. The other issue types above, red-team probes included, go to a maintainer first. A PR follows only if the maintainer accepts the report."}
            </li>
            <li>
              {zh
                ? "維護者或社群成員把偵測用的 regex 寫完，再跑安全閘：要有真陽性和假陽性樣本、符合 schema、不跟現有規則衝突，而且在良性語料上 0 誤報是硬性條件。這道閘真的會擋。"
                : "A maintainer or community member writes the detection regex and runs the safety gate: true- and false-positive samples, schema compliance, no conflict with existing rules, and zero false positives on the benign corpus as a hard requirement. The gate really does block rules."}
            </li>
            <li>
              {zh ? "規則合併進 main，隨下一個版本發布。CI 先在 npm 上 stage，維護者用 2FA 核准後上線，再建立 GitHub release。從這一刻起，每一個讀 ATR 的引擎都能用它，不分廠商，也不分國家。" : "The rule merges to main and ships in the next release. CI stages it on npm, a maintainer approves it with 2FA, and the GitHub release follows. From then on it belongs to every engine that reads ATR, whatever the vendor or the country."}
            </li>
            <li>
              {zh
                ? "下一次量測時，你的 payload 會進到 benchmark 語料。"
                : "On the next measurement run, your payload joins the benchmark corpus."}
              {" "}
              <a
                href="https://github.com/Agent-Threat-Rule/agent-threat-rules/tree/main/data/measurements"
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue hover:underline"
              >
                data/measurements/&lt;source&gt;/
              </a>
              {zh
                ? " 底下的歷史檔，記錄每一次量測的 recall、precision、fp-rate。數字綁定版本，不會漂移。"
                : " keeps the recall, precision and fp-rate of every run, pinned to a version so the numbers cannot drift."}
            </li>
            <li>
              {zh
                ? "ATR 公開引用 recall 數字時，一定附上量測檔的路徑。你的貢獻，在公開的審計鏈裡查得到。"
                : "Every public recall figure ATR cites comes with the path to its measurement file, so your contribution can be traced in the public audit chain."}
            </li>
          </ol>
        </div>
      </Reveal>

      {/* ── Spec amendments ── */}
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {zh ? "想改 spec 本身" : "Want to change the spec itself"}
        </div>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="border border-fog p-6 mb-12">
          <p className="text-sm text-stone leading-relaxed mb-3">
            {zh
              ? "spec（SPEC.md）是所有相容引擎之間的契約，改它沒有加規則那麼直接。先開一個標題以 [RFC] 開頭的 issue，寫清楚要改什麼、為什麼改。接著公開徵求意見 14 天（複雜提案延長到 30 天），讓所有實作者看到並回應。之後才收 PR。破壞性變更（SemVer 主版號）還要另外提前 30 天公告。"
              : "The spec (SPEC.md) is the contract between all conforming engines, so changing it is less direct than adding a rule. First open an issue whose title starts with [RFC], saying what you want to change and why. Then leave a 14-day public comment window (30 days for complex proposals) so every implementer can see it and respond. After that, submit the PR. A breaking change (SemVer major bump) also needs 30 days' advance notice."}
          </p>
          <p className="text-sm text-stone leading-relaxed mb-3">
            {zh
              ? "完整流程寫在治理頁的「決策流程」段落。"
              : "The full process is under Decision-making on the governance page."}
          </p>
          <div className="flex flex-wrap gap-4">
            <a
              href="https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new?title=%5BRFC%5D+"
              target="_blank"
              rel="noopener noreferrer"
              className="font-data text-xs text-blue hover:underline"
            >
              {zh ? "開 RFC issue" : "Open an RFC issue"} &rarr;
            </a>
            <span className="text-fog">|</span>
            <a
              href={`/${locale}/governance`}
              className="font-data text-xs text-blue hover:underline"
            >
              {zh ? "決策流程細節" : "Decision-making process"} &rarr;
            </a>
            <span className="text-fog">|</span>
            <a
              href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/SPEC.md"
              target="_blank"
              rel="noopener noreferrer"
              className="font-data text-xs text-blue hover:underline"
            >
              SPEC.md &rarr;
            </a>
          </div>
        </div>
      </Reveal>

      {/* ── First-time contributors ── */}
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {zh ? "第一次貢獻" : "First time contributing"}
        </div>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="border border-fog p-6 mb-12 text-sm text-graphite leading-relaxed space-y-3">
          <p>
            {zh
              ? "想幫忙，但不知道從哪裡下手？有兩個門檻低的入口："
              : "Want to help but not sure where to start? Two easy ways in:"}
          </p>
          <ul className="list-disc pl-6 space-y-2">
            <li>
              <a
                href="https://github.com/Agent-Threat-Rule/agent-threat-rules/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22"
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue hover:underline"
              >
                {zh ? "標了「good first issue」的未關閉 issue" : "Open issues labelled 'good first issue'"}
              </a>
              {zh
                ? "：維護者標過、範圍清楚的入門任務。"
                : ": starter tasks a maintainer has tagged, each with a clear scope."}
            </li>
            <li>
              {zh
                ? "誤判回報。工作中碰到規則誤判，花 15 分鐘填表，就能直接幫到下游所有採用者。維護者最重視這類回饋。"
                : "False-positive reports. If a rule misfires in your workflow, a 15-minute report directly helps every downstream adopter. Maintainers put this kind of feedback first."}
            </li>
          </ul>
        </div>
      </Reveal>

      {/* ── Become a maintainer ── */}
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {zh ? "想成為維護者" : "Want to become a maintainer"}
        </div>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="border border-fog p-6 mb-12 text-sm text-graphite leading-relaxed">
          <p className="mb-3">
            {zh
              ? "ATR 目前只有一位維護者，正在積極招募第二位、第三位。候選條件、決策結構和申請方式，都寫在治理頁。"
              : "ATR has a single maintainer today and is actively recruiting a second and a third. The candidate criteria, how decisions are made and how to apply are all on the governance page."}
          </p>
          <a href={`/${locale}/governance`} className="font-data text-xs text-blue hover:underline">
            {zh ? "看治理頁的「想成為維護者」" : "See 'Become a maintainer' on the governance page"} &rarr;
          </a>
        </div>
      </Reveal>

      {/* ── Optional: Threat Cloud reference service ── */}
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {zh ? "選用：Threat Cloud 參考服務" : "Optional: Threat Cloud reference service"}
        </div>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="border border-fog p-6 mb-6 text-sm text-stone leading-relaxed">
          <p>
            {zh
              ? "Threat Cloud 是 ATR 維護者營運的選用參考服務，不屬於標準本身。標準是規格加上 MIT 授權的規則，用 npm、PyPI 或直接拿 YAML，都能完全離線使用。Threat Cloud 只多了託管的方便，例如規則同步和威脅提交。不用它，也能得到同樣的結果。"
              : "Threat Cloud is an optional reference service run by the ATR maintainers. It is not part of the standard. The standard is the spec plus the MIT-licensed rules, fully usable offline through npm, PyPI or the raw YAML. Threat Cloud only adds hosted convenience, such as rule sync and threat submission. You can get the same results without it."}
          </p>
        </div>
      </Reveal>
      <Reveal>
        <div className="border border-fog mb-10">
          <div className="px-6 py-4 border-b border-fog bg-ash">
            <h2 className="font-display text-base font-semibold">
              {zh ? "Threat Cloud 自動化流程（選用）" : "The Threat Cloud auto-pipeline (optional)"}
            </h2>
            <p className="text-sm text-stone mt-1">
              {zh
                ? "規則正式的產生方式，是上面「送出後會發生什麼」講的社群與維護者流程：issue → 草案 PR → 維護者寫 regex → 安全閘 → 合併 → 發布到 npm。下面是維護者在 Threat Cloud 上營運的選用自動化版本，目標是把同一套流程壓到幾個小時。用不用它，標準和規則都一樣。"
                : "The canonical way rules get made is the community and maintainer workflow under \"What happens after you contribute\" above (issue → draft PR → maintainer writes regex → safety gate → merge → npm publish). Below is the optional automated version the maintainers run on Threat Cloud, which aims to get that same flow down to hours. The standard and the rules are identical whether or not you use it."}
            </p>
          </div>
          <div className="p-5 md:p-6">
            <div className="font-data text-sm leading-[2.2] text-graphite">
              {(zh
                ? [
                    "在野外發現新的攻擊手法",
                    "LLM 分析攻擊的結構和意圖",
                    "自動產生 YAML 規則提案和測試案例",
                    "社群審查，再過精確度測試閘",
                    "合併進 ATR，所有下游引擎自動更新。",
                  ]
                : [
                    "A new attack pattern is spotted in the wild",
                    "An LLM analyzes the attack's structure and intent",
                    "A YAML rule proposal with test cases is generated automatically",
                    "Community review, then the precision test gate",
                    "Merged into ATR. Every downstream engine updates.",
                  ]
              ).map((step, i) => (
                <div key={i}>
                  {i > 0 && <div className="text-mist text-center pl-6">|</div>}
                  <div className="flex items-center gap-3">
                    <span className="text-blue font-bold">{i + 1}.</span>
                    <span>{step}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </Reveal>

      {/* ── Resources ── */}
      <Reveal>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-fog">
          <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/GOVERNANCE.md" target="_blank" rel="noopener noreferrer" className="bg-paper p-6 hover:bg-ash transition-colors">
            <div className="font-display text-sm font-semibold mb-1">{t(locale, "contribute.governance")}</div>
            <p className="text-sm text-stone">{t(locale, "contribute.governance.desc")}</p>
          </a>
          <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/CONTRIBUTORS.md" target="_blank" rel="noopener noreferrer" className="bg-paper p-6 hover:bg-ash transition-colors">
            <div className="font-display text-sm font-semibold mb-1">{t(locale, "contribute.contributors")}</div>
            <p className="text-sm text-stone">{t(locale, "contribute.contributors.desc")}</p>
          </a>
          <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/examples/how-to-write-a-rule.md" target="_blank" rel="noopener noreferrer" className="bg-paper p-6 hover:bg-ash transition-colors">
            <div className="font-display text-sm font-semibold mb-1">{t(locale, "contribute.guide")}</div>
            <p className="text-sm text-stone">{t(locale, "contribute.guide.desc")}</p>
          </a>
        </div>
      </Reveal>
    </div>
  );
}
