import { Reveal } from "@/components/Reveal";
import { locales, type Locale } from "@/lib/i18n";
import {
  loadAdopters,
  loadAdoptersVerification,
  tierLabel,
  tierDescription,
  adopterLogoUrl,
  type Adopter,
  type AdopterTier,
  type IntegrationType,
} from "@/lib/adopters";
import {
  IntegrationTypeIcon,
  integrationTypeLabel,
  integrationTypeHint,
} from "@/components/IntegrationTypeIcon";
import type { Metadata } from "next";
import { pageMetadata } from "@/lib/seo";
import { Seal } from "@/components/classical/Emblem";

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
    path: "/ecosystem",
    title: "Ecosystem: ATR adopters",
    description:
      "Standards bodies, security vendors, and open-source tooling that have merged Agent Threat Rules (ATR) into their own public repositories.",
  });
}

export default async function EcosystemPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";
  const adopters = loadAdopters();
  const verification = loadAdoptersVerification();

  // The wall shows MERGED adoption only — an integration counts once its
  // evidence PR is merged (status "shipped"). In-review and planning entries
  // stay tracked in ADOPTERS.md but are not displayed here, so the page is a
  // claim of what has actually landed, not what is in flight.
  const shippedOnly = (entries: Adopter[]) =>
    entries.filter((a) => a.status === "shipped");

  // Pair tiers with their entries in display order. Tier S is most prominent,
  // tier 4 (commercial) is separated visually so vendor implementations do not
  // dominate a page that is primarily about the standard's reach. Empty tiers
  // (after the shipped filter) are dropped rather than shown as empty states.
  const allSections: Array<{ tier: AdopterTier; entries: Adopter[] }> = [
    { tier: "S", entries: shippedOnly(adopters.tierS) },
    { tier: "1", entries: shippedOnly(adopters.tier1) },
    { tier: "2", entries: shippedOnly(adopters.tier2) },
    { tier: "3", entries: shippedOnly(adopters.tier3) },
  ];
  const sections = allSections.filter((s) => s.entries.length > 0);
  // Commercial is rendered after a separator so it reads as "vendors offering
  // hosted ATR" rather than "another tier of adoption".
  const commercial: Adopter[] = shippedOnly(adopters.tier4);
  // Total reflects only merged adopters shown on the wall.
  const shippedCount =
    sections.reduce((n, s) => n + s.entries.length, 0) + commercial.length;

  return (
    <div className="pt-20 pb-16 px-6 max-w-[1120px] mx-auto">
      {/* Header */}
      <Reveal>
        <Seal name="laurel" size={72} className="text-ink mb-7" />
        <div className="text-[13px] text-stone mb-3">
          {zh ? "生態系" : "Ecosystem"}
        </div>
      </Reveal>
      <Reveal delay={0.1}>
        <h1 className="text-[32px] md:text-[44px] leading-[1.12] tracking-[-0.03em] font-medium mb-2">
          {zh ? "誰在採用這個標準。" : "Who ships the standard."}
        </h1>
      </Reveal>
      <Reveal delay={0.2}>
        <p className="text-base text-stone font-light mb-3 max-w-[640px]">
          {zh
            ? "標準好不好，看有沒有人採用，不看它自己怎麼說。這一頁列出把 ATR 規則放進公開、可驗證成品裡的專案，有標準機構、資安廠商，也有開源工具。每一筆都有公開 repo 裡已合併的 pull request 為證，不是廠商的產品宣稱。採用的方式本身也是重點：企業用 pull request 整合，不是私下 fork。開放標準要的就是這種治理方式。"
            : "A standard is measured by adoption, not by what it says about itself. This page lists projects that ship ATR rules in public, verifiable work: standards bodies, security vendors and open-source tools. Each entry is backed by a merged pull request in a public repository, not by a vendor's product claim. How they adopted it matters too. Enterprises integrate through pull requests, not private forks, and that is how an open standard is meant to be governed."}
        </p>
      </Reveal>
      <Reveal delay={0.22}>
        <p className="text-base text-stone font-light mb-3 max-w-[640px]">
          {zh
            ? "這份清單唯一的機器可讀來源是 ADOPTERS.md。採用者自己提 PR 加進來，維護者不預先審核。格式符合 schema、附上公開可驗證的證據連結，就會合併。你的 PR 本身就是紀錄。"
            : "ADOPTERS.md is the single machine-readable source of truth for this list. Adopters add themselves by PR, and the maintainers do not pre-approve entries. A PR that matches the schema and carries a verifiable evidence link gets merged. Your PR is the record."}
        </p>
      </Reveal>
      <Reveal delay={0.25}>
        <p className="font-data text-xs text-stone tracking-wide mb-5">
          {zh ? "共計" : "Total"}: <span className="text-ink font-bold">{shippedCount}</span> {zh ? "個採用者" : "adopters"}
          {" · "}
          <a
            href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/ADOPTERS.md"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:underline"
          >
            ADOPTERS.md →
          </a>
          {verification && (
            <>
              {" · "}
              <a
                href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/data/adopters-verification.json"
                target="_blank"
                rel="noopener noreferrer"
                className="text-green hover:underline"
                title={
                  zh
                    ? "scripts/verify-adopters.mjs 每週拿每個證據連結去 GitHub 重驗：shipped 必須是 MERGED，in-review 必須是 OPEN"
                    : "scripts/verify-adopters.mjs re-checks every evidence link against GitHub weekly: shipped must be MERGED, in-review must be OPEN"
                }
              >
                {zh
                  ? `${verification.verifiedAt} 對 GitHub 重驗證據連結，${verification.ok}/${verification.total} 通過`
                  : `evidence re-verified against GitHub ${verification.verifiedAt}: ${verification.ok}/${verification.total}`}
              </a>
            </>
          )}
        </p>
      </Reveal>

      {/* Integration-shape legend — the Type field decoded for engineers */}
      <Reveal delay={0.28}>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-x-8 gap-y-3 mb-10 max-w-[820px]">
          {(
            [
              "engine",
              "rule-import",
              "category-subset",
              "adapter",
              "reference",
              "sidecar-proxy",
            ] as IntegrationType[]
          ).map((ty) => (
            <div key={ty} className="flex items-start gap-2">
              <IntegrationTypeIcon
                type={ty}
                size={14}
                className="text-stone mt-[3px] shrink-0"
              />
              <div>
                <span className="font-data text-[11px] text-ink">
                  {integrationTypeLabel(ty, locale)}
                </span>
                <span className="block text-[11px] text-stone leading-snug">
                  {integrationTypeHint(ty, locale)}
                </span>
              </div>
            </div>
          ))}
        </div>
      </Reveal>

      {/* Tier S / 1 / 2 / 3 — the standard's reach */}
      {sections.map(({ tier, entries }) => (
        <section key={tier} className="mb-12">
          <Reveal>
            <div className="text-[13px] text-stone mb-1">
              {tierLabel(tier, locale)} ({entries.length})
            </div>
          </Reveal>
          <Reveal delay={0.05}>
            <p className="text-sm text-stone font-light mb-5 max-w-[680px]">
              {tierDescription(tier, locale)}
            </p>
          </Reveal>
          {entries.length === 0 ? (
            <Reveal delay={0.1}>
              <div className="border border-dashed border-fog px-5 py-6 text-sm text-stone">
                {zh
                  ? "這一層目前還沒有採用者。把你的專案加進來："
                  : "No adopters in this tier yet. Add yours:"}{" "}
                <a
                  href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/ADOPTERS.md"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue hover:underline"
                >
                  ADOPTERS.md
                </a>
              </div>
            </Reveal>
          ) : (
            <Reveal delay={0.1}>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-px bg-fog">
                {entries.map((a) => (
                  <article key={a.name} className="bg-paper p-5">
                    <div className="flex items-center gap-3 mb-1">
                      {adopterLogoUrl(a) && (
                        <img
                          src={adopterLogoUrl(a)}
                          alt=""
                          width={28}
                          height={28}
                          loading="lazy"
                          referrerPolicy="no-referrer"
                          className="ring-1 ring-fog shrink-0"
                        />
                      )}
                      <h2 className="font-display text-base font-semibold text-ink flex-1">
                        {a.name}
                      </h2>
                      <StatusBadge status={a.status} zh={zh} />
                    </div>
                    <p className="font-data text-[11px] text-stone tracking-wide mb-2 uppercase">
                      {a.org}
                      {a.since && (
                        <>
                          {" · "}
                          {zh ? "自" : "since"} {a.since}
                        </>
                      )}
                      {" · "}
                      <span
                        className="text-ink/70 inline-flex items-center gap-1 align-middle"
                        title={integrationTypeHint(a.type, locale)}
                      >
                        <IntegrationTypeIcon type={a.type} size={12} className="shrink-0" />
                        {integrationTypeLabel(a.type, locale)}
                      </span>
                      {verification?.okByName[a.name] && (
                        <>
                          {" · "}
                          <span
                            className="text-green normal-case"
                            title={
                              zh
                                ? "最近一次自動重驗時，這個證據在 GitHub 上的狀態跟宣稱的一致"
                                : "On the last automated re-check, the GitHub state of this evidence matched the declared status"
                            }
                          >
                            {zh
                              ? `證據重驗 ${verification.verifiedAt}`
                              : `verified ${verification.verifiedAt}`}
                          </span>
                        </>
                      )}
                    </p>
                    <p className="text-sm text-stone leading-relaxed mb-3">
                      {a.integration}
                    </p>
                    {a.categories && a.categories.length > 0 && (
                      <p className="font-data text-[11px] text-stone mb-2">
                        {zh ? "類別：" : "Categories:"}{" "}
                        {a.categories.map((c) => (
                          <span key={c} className="text-ink mr-2">
                            {c}
                          </span>
                        ))}
                      </p>
                    )}
                    <a
                      href={a.evidence}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="font-data text-xs text-blue hover:underline"
                    >
                      {zh ? "證據連結 →" : "Evidence →"}
                    </a>
                  </article>
                ))}
              </div>
            </Reveal>
          )}
        </section>
      ))}

      {/* Tier 4 — commercial implementations, visually separated */}
      {commercial.length > 0 && (
        <section className="border-t border-fog pt-10 mt-4 mb-12">
          <Reveal>
            <div className="text-[13px] text-stone mb-1">
              {tierLabel("4", locale)} ({commercial.length})
            </div>
          </Reveal>
          <Reveal delay={0.05}>
            <p className="text-sm text-stone font-light mb-5 max-w-[680px]">
              {tierDescription("4", locale)}
            </p>
          </Reveal>
          <Reveal delay={0.1}>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-px bg-fog">
              {commercial.map((a) => (
                <article key={a.name} className="bg-paper p-5">
                  <div className="flex items-center gap-3 mb-1">
                    {adopterLogoUrl(a) && (
                      <img
                        src={adopterLogoUrl(a)}
                        alt=""
                        width={28}
                        height={28}
                        loading="lazy"
                        referrerPolicy="no-referrer"
                        className="ring-1 ring-fog shrink-0"
                      />
                    )}
                    <h2 className="font-display text-base font-semibold text-ink flex-1">
                      {a.name}
                    </h2>
                    <StatusBadge status={a.status} zh={zh} />
                  </div>
                  <p className="font-data text-[11px] text-stone tracking-wide mb-2 uppercase">
                    {a.org}
                  </p>
                  <p className="text-sm text-stone leading-relaxed mb-3">{a.integration}</p>
                  <a
                    href={a.evidence}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-data text-xs text-blue hover:underline"
                  >
                    {zh ? "前往 →" : "Visit →"}
                  </a>
                </article>
              ))}
            </div>
          </Reveal>
        </section>
      )}

      {/* Two-path CTA — Integration Request issue (in-flight) or ADOPTERS PR (shipped) */}
      <Reveal>
        <div className="mt-12 border border-fog px-6 py-6 grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <div className="text-[13px] text-stone mb-2">
              {zh ? "正在規劃整合" : "Planning an integration"}
            </div>
            <h3 className="font-display text-base font-semibold text-ink mb-2">
              {zh ? "開一個 Integration Request issue" : "Open an Integration Request issue"}
            </h3>
            <p className="text-sm text-stone mb-3 leading-relaxed">
              {zh
                ? "想要 spec 導讀、設計審查、你那個語言的範例程式碼，或想先討論整合要怎麼做，就走這條。維護者七天內回覆。讓整合的人不必自己摸索格式，本來就是標準該做的事。"
                : "Take this path if you want a spec walkthrough, a design review, sample code for your language, or a conversation about the shape of your integration. Maintainers respond within seven days. Part of a standard's job is to keep integrators from working out the format alone."}
            </p>
            <a
              href="https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new?template=integration-request.yml"
              target="_blank"
              rel="noopener noreferrer"
              className="font-data text-xs text-blue hover:underline"
            >
              {zh ? "開 issue →" : "Open issue →"}
            </a>
          </div>
          <div>
            <div className="text-[13px] text-stone mb-2">
              {zh ? "已經上線" : "Already shipped"}
            </div>
            <h3 className="font-display text-base font-semibold text-ink mb-2">
              {zh ? "提 PR 加進 ADOPTERS.md" : "Open a PR against ADOPTERS.md"}
            </h3>
            <p className="text-sm text-stone mb-3 leading-relaxed">
              {zh
                ? "整合已經公開、可以驗證，就直接走這條。格式符合 schema、附上證據連結，就會合併，維護者不預先審核採用者。你把自己寫進公開紀錄，跟 Cisco、Microsoft、MISP 列在同一份檔案裡。"
                : "If your integration is public and verifiable, take this path. Entries that match the schema and carry a verifiable evidence link get merged. Maintainers do not pre-approve adopters. You write yourself into the public record, in the same file as Cisco, Microsoft and MISP."}
            </p>
            <a
              href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/ADOPTERS.md"
              target="_blank"
              rel="noopener noreferrer"
              className="font-data text-xs text-blue hover:underline"
            >
              ADOPTERS.md →
            </a>
          </div>
        </div>
      </Reveal>

      {/* Badge */}
      <Reveal>
        <div className="mt-10 mb-3">
          <div className="text-[13px] text-stone mb-2">
            {zh ? "徽章" : "Badge"}
          </div>
          <p className="text-sm text-stone mb-3 max-w-[480px]">
            {zh
              ? "你的專案已經內建 ATR？在 README 加上這個徽章，讓下游知道你的偵測跟著的是一個有版本、可以公開審查的標準。"
              : "Does your project ship ATR? Add this badge to your README. It tells downstream users that your detections track a versioned standard that peers can review."}
          </p>
        </div>
      </Reveal>
      <Reveal delay={0.05}>
        <div className="border border-fog p-5">
          <div className="mb-3">
            <img
              src="https://img.shields.io/badge/ATR-Integrated-2563EB?style=flat&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0MCAzNiIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0yMCAwTDQwIDM2SDMwTDIwIDE4TDEwIDM2SDBMMjAgMFoiLz48L3N2Zz4=&logoColor=white"
              alt="ATR Integrated"
              className="h-6"
            />
          </div>
          <div className="font-data text-xs text-stone mb-1">Markdown:</div>
          <div className="bg-ash border border-fog px-4 py-3 font-data text-xs text-ink overflow-x-auto">
            [![ATR Integrated](https://img.shields.io/badge/ATR-Integrated-2563EB?style=flat)](https://agentthreatrule.org/ecosystem)
          </div>
        </div>
      </Reveal>
    </div>
  );
}

function StatusBadge({
  status,
  zh,
}: {
  status: Adopter["status"];
  zh: boolean;
}) {
  if (status === "shipped") {
    return (
      <span className="font-data text-[10px] text-green bg-green/10 px-2 py-0.5  uppercase tracking-wide shrink-0">
        {zh ? "已上線" : "shipped"}
      </span>
    );
  }
  if (status === "in-review") {
    return (
      <span className="font-data text-[10px] text-stone bg-fog/40 px-2 py-0.5  uppercase tracking-wide shrink-0">
        {zh ? "審查中" : "in review"}
      </span>
    );
  }
  return (
    <span className="font-data text-[10px] text-stone bg-fog/30 px-2 py-0.5  uppercase tracking-wide shrink-0">
      {zh ? "規劃中" : "planning"}
    </span>
  );
}
