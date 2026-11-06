import type { Metadata } from "next";
import { locales, type Locale } from "@/lib/i18n";
import { pageMetadata } from "@/lib/seo";
import { loadVersionLabels } from "@/lib/versions";
import { CONTACTS, LEGAL_DRAFT, REPO_URL } from "@/lib/legal";
import { DocsShell, Callout } from "@/components/DocsShell";
import Phrased from "@/components/Phrased";
import { Sign } from "@/components/Sign";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export async function generateMetadata({ params }: { params: Promise<{ locale: string }> }): Promise<Metadata> {
  const { locale } = await params;
  return {
    ...pageMetadata({
      locale,
      path: "/terms",
      title: locale === "zh" ? "使用條款" : "Terms of use",
      description: locale === "zh" ? "網站內容與 ATR 規則的授權、商標，以及沒有擔保的範圍。" : "The license for the site and the ATR rules, the trademarks, and what is not warranted.",
    }),
    ...(LEGAL_DRAFT ? { robots: { index: false, follow: true } } : {}),
  };
}

type B = { en: string; zh: string };

const SECTIONS: ReadonlyArray<{ h: B; body: B; link?: { href: string; label: string } }> = [
  {
    h: { en: "License", zh: "授權" },
    body: {
      en: "The rules, the specification, the reference engine and this site's source are in the ATR repository under the MIT license. You may use, copy, modify and redistribute them under its terms.",
      zh: "規則、規格、參考引擎與本網站的原始碼都在 ATR repository，以 MIT 授權釋出。你可以依授權條款使用、複製、修改與再散布。",
    },
    link: { href: `${REPO_URL}/blob/main/LICENSE`, label: "LICENSE" },
  },
  {
    h: { en: "Trademarks", zh: "商標" },
    body: {
      en: "“ATR”, “Agent Threat Rules” and the related designations are governed by the trademark policy. Other organizations' names and logos belong to their owners; showing them here records a public adoption or reference, not an endorsement.",
      zh: "「ATR」、「Agent Threat Rules」與相關標示依商標政策使用。其他組織的名稱與 logo 屬於其所有人；在這裡顯示，只代表一筆公開的採用或引用紀錄，不代表背書。",
    },
    link: { href: `${REPO_URL}/blob/main/TRADEMARK.md`, label: "TRADEMARK.md" },
  },
  {
    h: { en: "No warranty", zh: "不提供擔保" },
    body: {
      en: "Rules and software are provided as is, without warranty of any kind, as the MIT license states. Detection rules miss attacks and raise false positives; the published limitations and errata say where. Nothing on this site is legal advice or a statement that any system complies with a law or a standard.",
      zh: "規則與軟體依 MIT 授權「按現狀」提供，不附任何擔保。偵測規則會漏報、也會誤報，已知限制與勘誤寫明在哪裡。本網站任何內容都不是法律意見，也不代表任何系統符合任何法規或標準。",
    },
  },
  {
    h: { en: "Responsible use", zh: "負責任使用" },
    body: {
      en: "ATR is for defensive detection. The responsible-use policy describes intended use and misuse.",
      zh: "ATR 用於防禦性偵測。負責任使用政策說明預期用途與濫用情形。",
    },
  },
  {
    h: { en: "Contact", zh: "聯絡" },
    body: { en: `Questions about these terms: ${CONTACTS.general}.`, zh: `對這些條款有疑問：${CONTACTS.general}。` },
  },
];

export default async function TermsPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";
  const pick = (t: B) => (zh ? t.zh : t.en);
  const versions = await loadVersionLabels();

  return (
    <Phrased>
    <DocsShell locale={locale} path="/terms" eyebrow={zh ? "VIII. 說明與法律" : "VIII. Help and legal"} title={zh ? "使用條款" : "Terms of use"} generatedAt={versions.generatedAt}>
      {LEGAL_DRAFT && (
        <Callout label={zh ? "草稿" : "Draft"}>
          {zh ? "這份條款是草稿，待維護者核准後才生效。" : "These terms are a draft and take effect only when the maintainers approve them."}
        </Callout>
      )}
      <div className="mt-8 max-w-[720px]">
        {SECTIONS.map((s) => (
          <section key={s.h.en} className="py-5 border-t border-fog">
            <h2 className="text-[17px] text-ink">{pick(s.h)}</h2>
            <p className="mt-2 text-[14.5px] leading-[1.75] text-graphite">{pick(s.body)}</p>
            {s.link && <a href={s.link.href} className="mt-2 inline-block font-data text-[11.5px] text-blue hover:underline underline-offset-4">{s.link.label}<Sign name="diple" size={10} className="ml-1.5 align-[-1px]" /></a>}
          </section>
        ))}
      </div>
    </DocsShell>
    </Phrased>
  );
}
