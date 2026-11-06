import Link from "next/link";
import type { Metadata } from "next";
import { locales, type Locale } from "@/lib/i18n";
import { pageMetadata } from "@/lib/seo";
import { SectionHead } from "@/components/SectionHead";
import { SheetRow } from "@/components/Sheet";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export async function generateMetadata({ params }: { params: Promise<{ locale: string }> }): Promise<Metadata> {
  const { locale } = await params;
  return pageMetadata({
    locale,
    path: "/community/membership",
    title: locale === "zh" ? "機構會員" : "Organization membership",
    description:
      locale === "zh"
        ? "ATR 機構會員：依員工數分級的年費、會員得到什麼、什麼永遠免費、什麼不賣。"
        : "ATR organization membership: annual dues by headcount, what members get, what stays free, and what is not for sale.",
  });
}

// Dues are not invoiced until the fiscal host has confirmed in writing how
// membership dues are received. Until then the page shows the schedule and
// takes expressions of interest only.
const MEMBERSHIP_OPEN = false;
const CONTACT = "contact@agentthreatrule.org";

type B = { en: string; zh: string };

const TIERS: ReadonlyArray<{ name: string; who: B; fee: string }> = [
  { name: "Associate", who: { en: "Nonprofits, academic institutions, open source foundations, government bodies", zh: "非營利組織、學術機構、開源基金會、政府機關" }, fee: "$0" },
  { name: "Startup", who: { en: "Under 10 employees, or under US$1M revenue; first two years", zh: "員工 10 人以下或營收 100 萬美元以下；前兩年" }, fee: "$1,000" },
  { name: "Small", who: { en: "10–99 employees", zh: "員工 10–99 人" }, fee: "$5,000" },
  { name: "Medium", who: { en: "100–999 employees", zh: "員工 100–999 人" }, fee: "$15,000" },
  { name: "Large", who: { en: "1,000–4,999 employees", zh: "員工 1,000–4,999 人" }, fee: "$30,000" },
  { name: "Enterprise", who: { en: "5,000 employees or more", zh: "員工 5,000 人以上" }, fee: "$50,000" },
];

const FREE: ReadonlyArray<B> = [
  { en: "Using and implementing the rules and the specification (MIT licence).", zh: "使用與實作規則和規格（MIT 授權）。" },
  { en: "Joining the community as a person, writing and reviewing rules.", zh: "以個人身分加入社群、撰寫與審查規則。" },
  { en: "Being listed as an adopter, with public evidence of the integration.", zh: "附上整合的公開證據，列名為採用者。" },
];

const BENEFITS: ReadonlyArray<B> = [
  { en: "Logo by tier on the membership page, and a member case page.", zh: "會員頁依級別顯示 logo，並有一頁會員案例。" },
  { en: "One seat on the Members Council: one organization, one vote, at every tier. The Council advises on coverage priorities and crosswalk needs.", zh: "會員議會一席：不論級別，一個單位一票。議會對該優先覆蓋什麼、需要哪些框架對照提出建議。" },
  { en: "A written maintainers' briefing each quarter, with an optional call.", zh: "每季一份維護者書面簡報，可加一場選擇性的線上會議。" },
  { en: "A first response within 7 days on false-positive reports and integration issues you raise. A response time, not an outcome.", zh: "你提出的誤判回報與整合問題，7 天內第一次回應。承諾的是回應時間，不是結果。" },
  { en: "Help mapping your engine against the L1 conformance suite.", zh: "協助你把引擎拿去對照 L1 符規測試套件。" },
];

const NOT_FOR_SALE: ReadonlyArray<B> = [
  { en: "Influence over whether any rule is accepted, changed or rejected.", zh: "影響任何規則的接受、修改或拒絕。" },
  { en: "Early access to rules or to the specification. Drafts are public when they are written.", zh: "提早取得規則或規格。草稿寫出來就公開。" },
  { en: "A chair, a veto, or a seat that can outvote the technical maintainers.", zh: "主席、否決權，或能壓過技術維護者表決的席位。" },
  { en: "A private errata channel. Errors are corrected in public.", zh: "私下的勘誤管道。錯誤一律公開更正。" },
  { en: "The ATR-Certified conformance designation. It follows the public conformance suite results, never membership.", zh: "ATR-Certified 符規標示。它只看公開符規測試的結果，與會員資格無關。" },
];

export default async function MembershipPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";
  const prefix = `/${locale}`;
  const pick = (t: B) => (zh ? t.zh : t.en);

  return (
    <>
      <SheetRow grid>
      <div className="max-w-[1072px] px-6 md:px-14 pt-24 pb-24">
      <div className="font-data text-[11px] uppercase tracking-[0.1em] text-stone mb-6">
        <Link href={`${prefix}/community`} className="hover:text-ink">{zh ? "社群" : "Community"}</Link> <span className="text-mist">/ {zh ? "機構會員" : "Membership"}</span>
      </div>
      <h1 className="text-[36px] md:text-[44px] leading-[1.1] tracking-[-0.01em] font-medium text-ink text-balance">
        {zh ? "機構會員" : "Organization membership"}
      </h1>
      <p className="mt-5 text-[17px] leading-[1.6] text-graphite max-w-[640px] text-pretty">
        {zh
          ? "會員年費用在規則的維護、量測和審查。年費依全集團員工數分級。錢買得到曝光和一個建議席位，買不到任何一條規則的結果。"
          : "Dues pay for maintaining, measuring and reviewing the rules. They scale with an organization's consolidated headcount. Money buys visibility and an advisory seat. It never buys the outcome of a rule."}
      </p>

      {!MEMBERSHIP_OPEN && (
        <div className="mt-8 border border-fog bg-ash px-5 py-4 text-[14px] leading-[1.6] text-graphite">
          <span className="font-data text-[10px] uppercase tracking-[0.08em] text-high mr-2">{zh ? "尚未開放" : "Not yet open"}</span>
          {zh
            ? `會員費要等財務託管方 Open Source Collective 書面確認收取方式後才開始收。有興趣的單位請先寫信到 ${CONTACT}。`
            : `Dues will be invoiced once the fiscal host, Open Source Collective, has confirmed in writing how they are received. Interested organizations can write to ${CONTACT} in the meantime.`}
        </div>
      )}

      <section className="mt-12" aria-labelledby="tiers-heading">
        <h2 id="tiers-heading" className="font-data text-[11px] uppercase tracking-[0.1em] text-stone mb-4">{zh ? "年費（美元）" : "Annual dues (USD)"}</h2>
        <table className="w-full text-left border-t border-fog">
          <thead>
            <tr className="border-b border-fog font-data text-[10.5px] uppercase tracking-[0.08em] text-mist">
              <th className="py-3 font-normal">{zh ? "級別" : "Tier"}</th>
              <th className="py-3 font-normal">{zh ? "適用" : "Who"}</th>
              <th className="py-3 font-normal text-right">{zh ? "年費" : "Per year"}</th>
            </tr>
          </thead>
          <tbody>
            {TIERS.map((tier) => (
              <tr key={tier.name} className="border-b border-fog">
                <td className="py-4 pr-4 text-[15px] text-ink">{tier.name}</td>
                <td className="py-4 pr-4 text-[13.5px] text-graphite">{pick(tier.who)}</td>
                <td className="py-4 text-[15px] text-ink text-right tabular-nums">{tier.fee}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <ul className="mt-4 flex flex-col gap-1.5 text-[13px] leading-[1.6] text-stone">
          <li>{zh ? "員工數以全集團計算，含母公司與關係企業，不含約聘。" : "Headcount is consolidated: parent and affiliates included, contractors excluded."}</li>
          <li>{zh ? "總部位於世界銀行列為低所得或中低所得國家的單位，Startup 到 Medium 級付 40%。" : "Organizations headquartered in a World Bank low or lower-middle income country pay 40% of the Startup to Medium rates."}</li>
          <li>{zh ? "國家版的語系或規則包屬於專案工作，另外報價，與會員資格無關。" : "National locale packs or rule packs are project work, quoted separately from membership."}</li>
          <li>{zh ? "會費付給 Open Source Collective（EIN 82-2037583，美國 501(c)(6) 非營利組織），不能抵稅。價目表與折扣一律公開。" : "Dues are paid to Open Source Collective (EIN 82-2037583, a US 501(c)(6) non-profit) and are not tax-deductible. The schedule and every discount are public."}</li>
        </ul>
      </section>

      <div className="mt-14 grid md:grid-cols-3 gap-10">
        <section>
          <SectionHead mark="§1" label={zh ? "永遠免費" : "Always free"} title={zh ? "不需要會員" : "No membership needed"} />
          <ul className="flex flex-col gap-3">{FREE.map((f) => <li key={f.en} className="text-[13.5px] leading-[1.6] text-graphite border-t border-fog pt-3">{pick(f)}</li>)}</ul>
        </section>
        <section>
          <SectionHead mark="§2" label={zh ? "會員得到" : "Members get"} title={zh ? "做得到的承諾" : "Promises that can be kept"} />
          <ul className="flex flex-col gap-3">{BENEFITS.map((f) => <li key={f.en} className="text-[13.5px] leading-[1.6] text-graphite border-t border-fog pt-3">{pick(f)}</li>)}</ul>
        </section>
        <section>
          <SectionHead mark="§3" label={zh ? "不賣" : "Not for sale"} title={zh ? "付錢也拿不到" : "At any price"} />
          <ul className="flex flex-col gap-3">{NOT_FOR_SALE.map((f) => <li key={f.en} className="text-[13.5px] leading-[1.6] text-graphite border-t border-fog pt-3">{pick(f)}</li>)}</ul>
        </section>
      </div>

      <section className="mt-14 border-t border-fog pt-8">
        <SectionHead
          mark="§4"
          label={zh ? "反壟斷" : "Antitrust"}
          title={zh ? "會員議會不談什麼" : "What the Members Council does not discuss"}
          body={
            zh
              ? "價格、客戶、市場劃分，以及誰可以或不可以實作 ATR。會員資格對任何符合公開價目表的單位開放；非會員在草稿公開時與會員同時看到，並有相同的意見期。"
              : "Prices, customers, market allocation, or who may or may not implement ATR. Membership is open to any organization at the published rate; non-members see every draft when members do and get the same comment period."
          }
        />
      </section>
      </div>
      </SheetRow>
    </>
  );
}
