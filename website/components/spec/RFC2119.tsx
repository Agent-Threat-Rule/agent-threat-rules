import type { Locale } from "@/lib/i18n";
import { Sign } from "@/components/Sign";

const COPY: Record<Locale, string> = {
  en: 'The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.',
  zh: '本文件中關鍵詞「MUST」、「MUST NOT」、「REQUIRED」、「SHALL」、「SHALL NOT」、「SHOULD」、「SHOULD NOT」、「RECOMMENDED」、「MAY」、「OPTIONAL」的詮釋方式依 RFC 2119 規範解讀(專有詞彙保留英文)。',
};

/**
 * Standards-site RFC 2119 boilerplate callout. Drop in at the top of any
 * page that uses MUST/SHOULD/MAY language.
 */
export function RFC2119({ locale }: { locale: Locale }) {
  return (
    <aside className="rfc2119 not-prose" role="note">
      <strong>RFC 2119.</strong> {COPY[locale]}{" "}
      <a
        href="https://datatracker.ietf.org/doc/html/rfc2119"
        target="_blank"
        rel="noopener noreferrer"
        className="text-navy underline"
      >
        IETF RFC 2119<Sign name="diple" size={10} className="ml-1.5 align-[-1px]" />
      </a>
    </aside>
  );
}
