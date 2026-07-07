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

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export const metadata: Metadata = {
  title: "Ecosystem — ATR adopters",
  description:
    "Standards bodies, production deployments, and open-source tooling that ship Agent Threat Rules (ATR).",
};

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
        <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">
          {zh ? "生態系" : "Ecosystem"}
        </div>
      </Reveal>
      <Reveal delay={0.1}>
        <h1 className="font-display text-[clamp(28px,4vw,44px)] font-extrabold tracking-[-2px] mb-2">
          {zh ? "誰在採用這個標準。" : "Who ships the standard."}
        </h1>
      </Reveal>
      <Reveal delay={0.2}>
        <p className="text-base text-stone font-light mb-3 max-w-[640px]">
          {zh
            ? "一個標準靠採用衡量,不靠宣稱。這頁列的是把 ATR 規則綁進公開、可驗證成品的專案——標準機構、生產部署、開源工具——而採用的形狀本身就是重點:企業整合走 pull request,不是私有 fork。這正是一個開放標準想要的治理質感。"
            : "A standard is measured by adoption, not by assertion. This page lists projects that ship ATR rules in public, verifiable work — standards bodies, production deployments, open-source tooling. The shape of that adoption is itself the point: enterprises integrate through pull requests, not private forks. That is the governance texture an open standard is built for."}
        </p>
      </Reveal>
      <Reveal delay={0.22}>
        <p className="text-base text-stone font-light mb-3 max-w-[640px]">
          {zh
            ? "ADOPTERS.md 是這份清單的單一機器可讀來源。採用者自行提 PR 加入,維護者不預先審核;只要 schema 對、附上公開可驗證的證據連結就 merge——你的 PR 本身就是紀錄。"
            : "ADOPTERS.md is the single machine-readable source of truth for this list. Adopters self-declare via PR — the maintainers do not pre-approve entries. A schema-conforming PR with a verifiable evidence link gets merged; your PR is the record."}
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
                    ? "scripts/verify-adopters.mjs 每週對 GitHub 重驗每個證據連結:shipped 必須是 MERGED,in-review 必須是 OPEN"
                    : "scripts/verify-adopters.mjs re-checks every evidence link against GitHub weekly: shipped must be MERGED, in-review must be OPEN"
                }
              >
                {zh
                  ? `證據連結 ${verification.verifiedAt} 對 GitHub 現驗 ${verification.ok}/${verification.total}`
                  : `evidence re-verified against GitHub ${verification.verifiedAt} — ${verification.ok}/${verification.total}`}
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
            <div className="font-data text-xs font-medium text-stone tracking-[2px] uppercase mb-1">
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
                  ? "目前還沒有採用者列在這一層。把你的專案加進來:"
                  : "No adopters listed in this tier yet. Add yours:"}{" "}
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
                          className="rounded-sm ring-1 ring-fog shrink-0"
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
                                ? "此證據連結最近一次自動重驗時,GitHub 上的狀態與宣稱相符"
                                : "On the last automated re-check, the GitHub state of this evidence matched the declared status"
                            }
                          >
                            {zh
                              ? `證據現驗 ${verification.verifiedAt}`
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
                        {zh ? "類別:" : "Categories:"}{" "}
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
            <div className="font-data text-xs font-medium text-stone tracking-[2px] uppercase mb-1">
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
                        className="rounded-sm ring-1 ring-fog shrink-0"
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
            <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-2">
              {zh ? "規劃整合中" : "Planning an integration"}
            </div>
            <h3 className="font-display text-base font-semibold text-ink mb-2">
              {zh ? "開 Integration Request issue" : "Open an Integration Request issue"}
            </h3>
            <p className="text-sm text-stone mb-3 leading-relaxed">
              {zh
                ? "想要 spec walkthrough、design review、你的語言的 sample code,或先討論整合形狀,就走這條。維護者七天內回覆——標準的責任之一,是讓整合的人不必獨自摸索格式。"
                : "If you want a spec walkthrough, design review, sample code for your language, or to discuss the shape of your integration, this is the path. Maintainers respond within seven days — part of a standard's job is to keep integrators from reinventing the format alone."}
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
            <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-2">
              {zh ? "已經 ship 了" : "Already shipped"}
            </div>
            <h3 className="font-display text-base font-semibold text-ink mb-2">
              {zh ? "提 PR 加進 ADOPTERS.md" : "Open a PR against ADOPTERS.md"}
            </h3>
            <p className="text-sm text-stone mb-3 leading-relaxed">
              {zh
                ? "整合已經公開可驗證,直接走這條。Schema 對、附 evidence link 就 merge——維護者不預先審核採用者,把你自己寫進公開紀錄,跟 Cisco、Microsoft、MISP 列在同一份檔案。"
                : "If your integration is publicly verifiable, take this path. Schema-conforming entries with a verifiable evidence link get merged — maintainers do not pre-approve adopters. You write yourself into the public record, in the same file as Cisco, Microsoft, and MISP."}
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
          <div className="font-data text-xs font-medium text-stone tracking-[2px] uppercase mb-2">
            {zh ? "徽章" : "Badge"}
          </div>
          <p className="text-sm text-stone mb-3 max-w-[480px]">
            {zh
              ? "你的專案 ship 了 ATR?在 README 加上這個徽章——讓下游知道你的偵測規則對著一個版本化、可審查的標準。"
              : "Your project ships ATR? Add this badge to your README — it tells downstream that your detections track a versioned, peer-reviewable standard."}
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
      <span className="font-data text-[10px] text-green bg-green/10 px-2 py-0.5 rounded-sm uppercase tracking-wide shrink-0">
        {zh ? "已上線" : "shipped"}
      </span>
    );
  }
  if (status === "in-review") {
    return (
      <span className="font-data text-[10px] text-stone bg-fog/40 px-2 py-0.5 rounded-sm uppercase tracking-wide shrink-0">
        {zh ? "審查中" : "in review"}
      </span>
    );
  }
  return (
    <span className="font-data text-[10px] text-stone bg-fog/30 px-2 py-0.5 rounded-sm uppercase tracking-wide shrink-0">
      {zh ? "規劃中" : "planning"}
    </span>
  );
}
