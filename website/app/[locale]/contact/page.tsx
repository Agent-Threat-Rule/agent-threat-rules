import Link from "next/link";
import type { Metadata } from "next";
import type { ReactNode } from "react";
import { locales, type Locale } from "@/lib/i18n";
import { pageMetadata } from "@/lib/seo";
import { loadVersionLabels } from "@/lib/versions";
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
    path: "/contact",
    title: locale === "zh" ? "聯絡" : "Contact",
    description: locale === "zh" ? "依事由找到對的聯絡方式：一般、資安漏洞、商標、加入社群、錯誤回報。" : "The right channel for each reason: general, security vulnerabilities, trademark, joining, and bug reports.",
  });
}

const a = "text-blue hover:underline underline-offset-4";

export default async function ContactPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";
  const p = `/${locale}`;
  const versions = await loadVersionLabels();

  const rows: ReadonlyArray<{ reason: string; channel: ReactNode; note: string }> = [
    { reason: zh ? "一般" : "General", channel: <a href={`mailto:${CONTACTS.general}`} className={a}>{CONTACTS.general}</a>, note: zh ? "合作、媒體、其他" : "Partnerships, press, anything else" },
    {
      reason: zh ? "資安漏洞" : "Security vulnerability",
      channel: <><a href={`${REPO_URL}/security/advisories/new`} className={a}>{zh ? "GitHub 私下回報" : "GitHub private report"}</a>{zh ? " 或 " : " or "}<a href={`mailto:${CONTACTS.security}`} className={a}>{CONTACTS.security}</a></>,
      note: zh ? "請勿開公開 issue；見 SECURITY.md" : "Do not open a public issue; see SECURITY.md",
    },
    { reason: zh ? "商標" : "Trademark", channel: <a href={`mailto:${CONTACTS.trademark}`} className={a}>{CONTACTS.trademark}</a>, note: zh ? "標示使用；見 TRADEMARK.md" : "Use of the marks; see TRADEMARK.md" },
    { reason: zh ? "加入社群" : "Joining", channel: <span>{zh ? "暫停受理" : "Paused"}</span>, note: zh ? "隱私說明定稿後開放" : "Opens once the privacy notice is final" },
    { reason: zh ? "錯誤、誤判、繞過" : "Bugs, false positives, bypasses", channel: <a href={`${REPO_URL}/issues/new/choose`} className={a}>GitHub issues</a>, note: zh ? "有對應表單" : "There is a form for each" },
    { reason: zh ? "問題與討論" : "Questions and discussion", channel: <a href={`${REPO_URL}/discussions`} className={a}>GitHub Discussions</a>, note: zh ? "公開，任何人可回答" : "Public; anyone can answer" },
  ];

  return (
    <Phrased>
    <DocsShell
      locale={locale}
      path="/contact"
      eyebrow={zh ? "VIII. 說明與法律" : "VIII. Help and legal"}
      title={zh ? "聯絡" : "Contact"}
      lead={zh ? "依事由選管道。公開管道的回覆別人也看得到，能幫到下一個人。" : "Pick the channel by reason. Answers in public channels help the next person too."}
      generatedAt={versions.generatedAt}
    >
      <dl className="border-t border-fog">
        {rows.map((r) => (
          <div key={r.reason} className="grid md:grid-cols-[200px_1fr_1fr] gap-2 md:gap-4 py-4 border-b border-fog">
            <dt className="text-[14px] text-ink">{r.reason}</dt>
            <dd className="text-[14px]">{r.channel}</dd>
            <dd className="text-[13px] text-stone">{r.note}</dd>
          </div>
        ))}
      </dl>
    </DocsShell>
    </Phrased>
  );
}
