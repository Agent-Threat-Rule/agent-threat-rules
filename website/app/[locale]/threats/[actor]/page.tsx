import { notFound } from "next/navigation";
import Link from "next/link";
import type { Metadata } from "next";
import { Reveal } from "@/components/Reveal";
import { locales, type Locale } from "@/lib/i18n";
import { getActor, listActors } from "@/lib/actors";

export function generateStaticParams() {
  const params: { locale: string; actor: string }[] = [];
  for (const locale of locales) {
    for (const actor of listActors()) {
      params.push({ locale, actor: actor.slug });
    }
  }
  return params;
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string; actor: string }>;
}): Promise<Metadata> {
  const { locale: rawLocale, actor: slug } = await params;
  const actor = getActor(slug);
  if (!actor) return { title: "Actor Not Found — ATR" };
  const zh = rawLocale === "zh";
  return {
    title: `Actor Profile: ${actor.name} | ATR`,
    description: zh ? actor.summary.zh : actor.summary.en,
  };
}

export default async function ActorPage({
  params,
}: {
  params: Promise<{ locale: string; actor: string }>;
}) {
  const { locale: rawLocale, actor: slug } = await params;
  const locale = (locales.includes(rawLocale as Locale) ? rawLocale : "en") as Locale;
  const zh = locale === "zh";
  const prefix = `/${locale}`;
  const actor = getActor(slug);
  if (!actor) notFound();

  const statusLabel: Record<typeof actor.status, { en: string; zh: string }> = {
    active: { en: "Active", zh: "活躍中" },
    dormant: { en: "Dormant", zh: "休眠" },
    takedown: { en: "Taken down", zh: "已下架" },
  };

  return (
    <div className="pt-20 pb-20 px-5 md:px-6 max-w-[1120px] mx-auto">
      {/* Breadcrumb */}
      <div className="font-data text-xs text-stone mb-6">
        <Link href={`${prefix}`} className="hover:text-ink transition-colors">
          {zh ? "首頁" : "Home"}
        </Link>
        <span className="text-fog mx-2">/</span>
        <Link href={`${prefix}/threats`} className="hover:text-ink transition-colors">
          {zh ? "威脅情報" : "Threat Feed"}
        </Link>
        <span className="text-fog mx-2">/</span>
        <span className="text-ink">{actor.name}</span>
      </div>

      {/* Header */}
      <Reveal>
        <div className="font-data text-[11px] md:text-xs font-medium text-critical tracking-[1.5px] md:tracking-[3px] uppercase mb-3">
          {zh ? "威脅行為者檔案" : "Threat Actor Profile"}
        </div>
      </Reveal>
      <Reveal delay={0.05}>
        <h1 className="font-display text-[clamp(32px,5vw,56px)] font-extrabold tracking-[-2px] md:tracking-[-3px] leading-[1.05] text-ink break-all">
          {actor.name}
        </h1>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="flex flex-wrap items-center gap-3 mt-4">
          <span className="font-data text-[10px] md:text-xs font-bold text-critical bg-critical/10 px-2 py-1 rounded-[2px] uppercase tracking-wide">
            {statusLabel[actor.status][locale]}
          </span>
          <span className="font-data text-xs text-stone">
            {actor.skillsMalicious} / {actor.skillsPublished} {zh ? "惡意" : "malicious"} ({actor.malRatio})
          </span>
          <span className="text-fog">·</span>
          <span className="font-data text-xs text-stone">
            {zh ? "首次發現 " : "First seen "}{actor.firstSeen}
          </span>
        </div>
      </Reveal>
      <Reveal delay={0.15}>
        <p className="text-sm md:text-base text-graphite max-w-[720px] mt-5 md:mt-6 leading-[1.8]">
          {zh ? actor.summary.zh : actor.summary.en}
        </p>
      </Reveal>

      {/* Overview table */}
      <Section label={zh ? "檔案概要" : "Overview"} delay={0.2}>
        <dl className="grid grid-cols-1 sm:grid-cols-2 gap-px bg-fog">
          <DataRow label={zh ? "首次發現" : "First seen"} value={actor.firstSeen} />
          <DataRow label={zh ? "最新活動" : "Last activity"} value={actor.lastActivity} />
          <DataRow
            label={zh ? "已發布 skill" : "Skills published"}
            value={actor.skillsPublished.toString()}
          />
          <DataRow
            label={zh ? "惡意比例" : "Malicious ratio"}
            value={`${actor.skillsMalicious} / ${actor.skillsPublished} (${actor.malRatio})`}
          />
          <DataRow
            label={zh ? "主要動機" : "Primary motive"}
            value={zh ? actor.motive.zh : actor.motive.en}
          />
          <DataRow
            label={zh ? "地理線索" : "Geography"}
            value={zh ? actor.geography.zh : actor.geography.en}
          />
        </dl>
      </Section>

      {/* TTPs */}
      <Section label={zh ? "戰術、技術、程序 (TTPs)" : "Tactics, Techniques & Procedures"} delay={0.25}>
        <SubSection title={zh ? "偽裝手法" : "Disguises"}>
          <ul className="space-y-2">
            {actor.disguises.map((d, i) => (
              <li key={i} className="text-sm text-graphite leading-[1.7] flex items-start gap-2">
                <span className="text-fog shrink-0 mt-1">▸</span>
                <span>{zh ? d.zh : d.en}</span>
              </li>
            ))}
          </ul>
        </SubSection>
        <SubSection title={zh ? "Payload 遞送" : "Payload mechanisms"}>
          <ol className="space-y-3 list-none">
            {actor.payloadMechanisms.map((m, i) => (
              <li key={i} className="text-sm text-graphite leading-[1.7] pl-8 relative">
                <span className="absolute left-0 top-0 font-data text-xs text-mist">
                  {String(i + 1).padStart(2, "0")}
                </span>
                {zh ? m.zh : m.en}
              </li>
            ))}
          </ol>
        </SubSection>
        {actor.socialEngineering && actor.socialEngineering.length > 0 && (
          <SubSection title={zh ? "社交工程樣本" : "Social engineering samples"}>
            <div className="space-y-2">
              {actor.socialEngineering.map((s, i) => (
                <blockquote
                  key={i}
                  className="font-data text-xs md:text-sm bg-ash border-l-2 border-critical px-3 py-2 text-graphite"
                >
                  {s}
                </blockquote>
              ))}
            </div>
          </SubSection>
        )}
      </Section>

      {/* IOCs */}
      <Section label={zh ? "入侵指標 (IOCs)" : "Indicators of Compromise"} delay={0.3}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {actor.iocs.c2Servers && actor.iocs.c2Servers.length > 0 && (
            <IocBlock title={zh ? "C2 伺服器" : "C2 servers"} items={actor.iocs.c2Servers} />
          )}
          {actor.iocs.urls && actor.iocs.urls.length > 0 && (
            <IocBlock title="URLs" items={actor.iocs.urls} />
          )}
          {actor.iocs.filePatterns && actor.iocs.filePatterns.length > 0 && (
            <IocBlock title={zh ? "檔案樣態" : "File patterns"} items={actor.iocs.filePatterns} />
          )}
          {actor.iocs.namingPatterns && actor.iocs.namingPatterns.length > 0 && (
            <IocBlock
              title={zh ? "命名樣態" : "Naming patterns"}
              items={actor.iocs.namingPatterns}
            />
          )}
          {actor.iocs.passwords && actor.iocs.passwords.length > 0 && (
            <IocBlock title={zh ? "已知密碼" : "Known passwords"} items={actor.iocs.passwords} />
          )}
        </div>
        {actor.iocs.base64Samples && actor.iocs.base64Samples.length > 0 && (
          <div className="mt-6">
            <div className="font-data text-[11px] text-stone tracking-[2px] uppercase mb-2">
              {zh ? "Base64 樣本" : "Base64 samples"}
            </div>
            <div className="bg-ash border border-fog p-4 font-data text-xs text-graphite overflow-x-auto leading-[1.8]">
              {actor.iocs.base64Samples.map((s, i) => (
                <div key={i} className="break-all">
                  {s}
                </div>
              ))}
            </div>
            <p className="text-xs text-mist mt-2 leading-[1.7]">
              {zh
                ? "僅在隔離環境下解碼:`echo \"...\" | base64 -d` 會還原原始 payload。請勿在正式機器上執行。"
                : 'Decode in an isolated environment only: `echo "..." | base64 -d` recovers the raw payload. Do not run it on a live machine.'}
            </p>
          </div>
        )}
      </Section>

      {/* Related ATR Rules */}
      <Section label={zh ? "對應的 ATR 規則" : "Detection Coverage"} delay={0.35}>
        {actor.atrRules.length > 0 ? (
          <>
            <div className="flex flex-wrap gap-2">
              {actor.atrRules.map((rid) => (
                <Link
                  key={rid}
                  href={`${prefix}/rules/${rid}`}
                  className="font-data text-xs md:text-sm bg-paper border border-fog hover:border-stone px-3 py-1.5 rounded-[2px] text-ink transition-colors"
                >
                  {rid}
                </Link>
              ))}
            </div>
            <p className="text-xs text-mist mt-3 leading-[1.7]">
              {zh
                ? "每個規則 ID 永久穩定（ATR-YYYY-NNNNN），對外引用安全。點開可看完整 YAML 定義、攻擊樣本與已記錄的規避手法。"
                : "Each rule ID is permanent and stable (ATR-YYYY-NNNNN), safe to cite. Open one for the full YAML definition, attack samples, and documented evasion techniques."}
            </p>
          </>
        ) : (
          <p className="text-sm text-mist leading-[1.7]">
            {zh
              ? "這個行為者的手法尚無對應的已發布規則。偵測規則一經審查合併便會列於此處。"
              : "No published rule maps to this actor's techniques yet. Detection rules appear here once reviewed and merged."}
          </p>
        )}
      </Section>

      {/* Framework mappings */}
      <Section label={zh ? "上層框架對照" : "Maps to Established Frameworks"} delay={0.4}>
        <div className="space-y-5">
          <div>
            <div className="font-data text-[11px] text-stone tracking-[2px] uppercase mb-2">
              MITRE ATLAS
            </div>
            <div className="flex flex-wrap gap-2">
              {actor.atlas.map((a) => (
                <span
                  key={a.id}
                  className="font-data text-xs bg-ash px-2.5 py-1 rounded-[2px] text-ink"
                >
                  {a.id} · {a.name}
                </span>
              ))}
            </div>
          </div>
          {actor.owasp.map((group) => (
            <div key={group.framework}>
              <div className="font-data text-[11px] text-stone tracking-[2px] uppercase mb-2">
                {group.framework}
              </div>
              <ul className="space-y-1.5">
                {group.items.map((item) => (
                  <li key={item} className="font-data text-xs md:text-sm text-graphite">
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </Section>

      {/* Affected registries */}
      <Section label={zh ? "受影響的 Registry" : "Affected Registries"} delay={0.45}>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-px bg-fog">
          {actor.registries.map((r) => (
            <div key={r.name} className="bg-paper p-5">
              <div className="font-data text-xs text-stone">{r.name}</div>
              <div className="font-data text-2xl font-bold text-ink mt-1">
                {r.count.toLocaleString()}
              </div>
              <div className="text-xs text-mist mt-1">
                {zh ? "個惡意 skill" : "malicious skills"}
              </div>
            </div>
          ))}
        </div>
      </Section>

      {/* Timeline */}
      <Section label={zh ? "時間線" : "Timeline"} delay={0.5}>
        <ol className="space-y-0">
          {actor.timeline.map((t, i) => (
            <li key={i} className="flex gap-4 md:gap-6 relative pl-1">
              <div className="font-data text-xs text-stone w-[92px] shrink-0 pt-1">{t.date}</div>
              <div className="flex flex-col items-center shrink-0 pt-2">
                <div className="w-2 h-2 rounded-full bg-ink" />
                {i < actor.timeline.length - 1 && (
                  <div className="w-px flex-1 bg-fog mt-1 min-h-[32px]" />
                )}
              </div>
              <div className="text-sm text-graphite leading-[1.7] pb-6">
                {zh ? t.event.zh : t.event.en}
              </div>
            </li>
          ))}
        </ol>
      </Section>

      {/* Reports / disclosure status */}
      <Section label={zh ? "通報狀態" : "Report Status"} delay={0.55}>
        <ul className="space-y-3">
          {actor.reports.map((r, i) => (
            <li key={i} className="flex items-start gap-3 flex-wrap">
              <span className="font-data text-xs text-stone shrink-0 mt-1">{r.platform}</span>
              {r.url ? (
                <a
                  href={r.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-data text-xs md:text-sm text-blue hover:underline"
                >
                  {r.id || (zh ? "連結" : "Link")} →
                </a>
              ) : r.id ? (
                <span className="font-data text-xs md:text-sm text-ink">{r.id}</span>
              ) : null}
              <span
                className={`font-data text-[10px] px-2 py-0.5 rounded-[2px] uppercase tracking-wide ${
                  r.status === "open"
                    ? "bg-high/10 text-high"
                    : r.status === "closed"
                      ? "bg-stone/10 text-stone"
                      : "bg-blue/10 text-blue"
                }`}
              >
                {r.status}
              </span>
            </li>
          ))}
        </ul>
      </Section>

      {/* Back link */}
      <div className="mt-14 md:mt-16 pt-6 border-t border-fog">
        <Link
          href={`${prefix}/threats`}
          className="font-data text-xs md:text-sm text-blue hover:underline"
        >
          {zh ? "← 回到威脅情報" : "← Back to threat feed"}
        </Link>
      </div>
    </div>
  );
}

function Section({
  label,
  children,
  delay = 0,
}: {
  label: string;
  children: React.ReactNode;
  delay?: number;
}) {
  return (
    <Reveal delay={delay}>
      <section className="mt-12 md:mt-16">
        <div className="font-data text-[11px] md:text-xs font-medium text-stone tracking-[1.5px] md:tracking-[3px] uppercase mb-4 md:mb-5">
          {label}
        </div>
        {children}
      </section>
    </Reveal>
  );
}

function SubSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mt-5 first:mt-0">
      <div className="font-display text-sm font-semibold text-ink mb-2.5">{title}</div>
      {children}
    </div>
  );
}

function DataRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-paper p-4 md:p-5">
      <dt className="font-data text-[11px] text-stone tracking-[1.5px] uppercase mb-1.5">
        {label}
      </dt>
      <dd className="text-sm text-ink leading-[1.6]">{value}</dd>
    </div>
  );
}

function IocBlock({ title, items }: { title: string; items: string[] }) {
  return (
    <div>
      <div className="font-data text-[11px] text-stone tracking-[2px] uppercase mb-2">{title}</div>
      <ul className="space-y-1.5">
        {items.map((item, i) => (
          <li
            key={i}
            className="font-data text-xs md:text-sm text-graphite bg-ash px-3 py-2 rounded-[2px] break-all"
          >
            {item}
          </li>
        ))}
      </ul>
    </div>
  );
}
