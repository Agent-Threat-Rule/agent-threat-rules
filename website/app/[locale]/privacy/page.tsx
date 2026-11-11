import type { Metadata } from "next";
import { locales, type Locale } from "@/lib/i18n";
import { pageMetadata } from "@/lib/seo";
import { loadVersionLabels } from "@/lib/versions";
import { CONTACTS, LEGAL_ADOPTED, LEGAL_DRAFT } from "@/lib/legal";
import { DocsShell, Callout } from "@/components/DocsShell";
import Phrased from "@/components/Phrased";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export async function generateMetadata({ params }: { params: Promise<{ locale: string }> }): Promise<Metadata> {
  const { locale } = await params;
  return {
    ...pageMetadata({
      locale,
      path: "/privacy",
      title: locale === "zh" ? "隱私說明" : "Privacy notice",
      description: locale === "zh" ? "這個網站收集什麼、不收集什麼，以及加入申請的資料怎麼處理。" : "What this site collects and does not collect, and how applications to join are handled.",
    }),
    ...(LEGAL_DRAFT ? { robots: { index: false, follow: true } } : {}),
  };
}

type B = { en: string; zh: string };

const SECTIONS: ReadonlyArray<{ h: B; body: B }> = [
  {
    h: { en: "Who is responsible", zh: "誰負責" },
    body: {
      en: `Adam Lin, the maintainer of ATR, is responsible for this site and for the data described here. The ATR Project is not a legal entity, so he is responsible personally. Contact: ${CONTACTS.general}.`,
      zh: `這個網站和這裡提到的資料，由 ATR 維護者 Adam Lin 負責。ATR Project 不是法人，所以由他個人負責。聯絡：${CONTACTS.general}。`,
    },
  },
  {
    h: { en: "What the site itself collects", zh: "網站本身收集什麼" },
    body: {
      en: "The site is static. Its own code loads no analytics or advertising scripts and sets no cookies. It is served by Cloudflare Pages, which processes request data, such as IP addresses, to deliver the pages, under Cloudflare's own privacy policy.",
      zh: "網站是靜態的。網站自己的程式碼沒有載入任何分析或廣告腳本，也不設 cookie。網站由 Cloudflare Pages 提供，Cloudflare 為了傳送頁面會處理請求資料（例如 IP 位址），依 Cloudflare 自己的隱私政策處理。",
    },
  },
  {
    h: { en: "Content loaded from other services", zh: "從其他服務載入的內容" },
    body: {
      en: "Some pages show avatars and logos from GitHub (github.com, avatars.githubusercontent.com) and badges from img.shields.io. Your browser requests those images from those services directly.",
      zh: "部分頁面會顯示來自 GitHub（github.com、avatars.githubusercontent.com）的頭像與 logo，以及 img.shields.io 的徽章。這些圖片由你的瀏覽器直接向這些服務請求。",
    },
  },
  {
    h: { en: "Applications to join", zh: "加入社群的申請" },
    body: {
      en: `How applicant data is handled is set out on the join page, under "How your data is handled" (last updated 2026-11-08); that notice governs applications. In short: an application through the GitHub form is a public issue on GitHub. An application by email is used only to reply and to draft your directory entry, and nothing is published until you confirm it. To have an application deleted or a listing removed, write to ${CONTACTS.general}.`,
      zh: `申請資料怎麼處理，以入會頁「你的資料怎麼處理」那一節為準（最後更新 2026-11-08）。簡單說：透過 GitHub 表單的申請，會是 GitHub 上的一則公開 issue。透過 email 的申請只用來回覆你、草擬你的名錄文字；你確認之前不會公開任何內容。要刪除申請或移除列名，請寫信到 ${CONTACTS.general}。`,
    },
  },
  {
    h: { en: "Email you send us", zh: "你寄來的 email" },
    body: {
      en: "Email to an agentthreatrule.org address is read by the maintainers and kept only as long as the conversation needs it.",
      zh: "寄到 agentthreatrule.org 信箱的 email 由維護者閱讀，只在對話需要的期間保留。",
    },
  },
  {
    h: { en: "Contact", zh: "聯絡" },
    body: { en: `Questions about this notice: ${CONTACTS.general}.`, zh: `對這份說明有疑問：${CONTACTS.general}。` },
  },
];

export default async function PrivacyPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";
  const pick = (t: B) => (zh ? t.zh : t.en);
  const versions = await loadVersionLabels();

  return (
    <Phrased>
    <DocsShell locale={locale} path="/privacy" eyebrow={zh ? "VIII. 說明與法律" : "VIII. Help and legal"} title={zh ? "隱私說明" : "Privacy notice"} generatedAt={versions.generatedAt}>
      {LEGAL_DRAFT && (
        <Callout label={zh ? "草稿" : "Draft"}>
          {zh ? "這份說明是草稿，待維護者核准後才生效。" : "This notice is a draft and takes effect only when the maintainers approve it."}
        </Callout>
      )}
      {!LEGAL_DRAFT && (
        <p className="mt-6 font-data text-[11.5px] text-stone">{zh ? `生效日 ${LEGAL_ADOPTED}` : `In effect from ${LEGAL_ADOPTED}`}</p>
      )}
      <div className="mt-8 max-w-[720px]">
        {SECTIONS.map((s) => (
          <section key={s.h.en} className="py-5 border-t border-fog">
            <h2 className="text-[17px] text-ink">{pick(s.h)}</h2>
            <p className="mt-2 text-[14.5px] leading-[1.75] text-graphite">{pick(s.body)}</p>
          </section>
        ))}
      </div>
    </DocsShell>
    </Phrased>
  );
}
