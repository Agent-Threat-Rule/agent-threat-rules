import Link from "next/link";
import type { ReactNode } from "react";

/**
 * A small Markdown renderer for the repository's own documents (crosswalks).
 * It builds React elements and never injects HTML, so a document cannot
 * smuggle markup into the site. Supported: headings, paragraphs, GFM tables,
 * lists, blockquotes, fenced code, rules; inline code, bold, italics, links.
 * ATR rule IDs become links to their rule pages; repository-relative links
 * point at the file on GitHub.
 */

const REPO_BLOB = "https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main";
const RULE_ID = /^ATR-\d{4}-\d{5}$/;

interface Ctx {
  locale: string;
  /** Repository directory of the document, to resolve relative links. */
  baseDir: string;
}

function resolveHref(href: string, ctx: Ctx): { href: string; internal: boolean } | null {
  if (/^https?:\/\//i.test(href) || /^mailto:/i.test(href)) return { href, internal: false };
  if (href.startsWith("#")) return { href, internal: false };
  if (/^[a-z][a-z0-9+.-]*:/i.test(href)) return null; // javascript:, data: and the like
  const parts = `${ctx.baseDir}/${href}`.split("/");
  const out: string[] = [];
  for (const p of parts) {
    if (p === "..") out.pop();
    else if (p && p !== ".") out.push(p);
  }
  return { href: `${REPO_BLOB}/${out.join("/")}`, internal: false };
}

const INLINE = /(`[^`]+`)|(\*\*[^*]+\*\*)|(\[[^\]]+\]\([^)\s]+\))|(ATR-\d{4}-\d{5})|(https?:\/\/[^\s)<>|]+)|(\*[^*\s][^*]*\*|_[^_\s][^_]*_)/g;

export function renderInline(text: string, ctx: Ctx, keyBase = "i"): ReactNode[] {
  const nodes: ReactNode[] = [];
  let last = 0;
  let k = 0;
  for (const m of text.matchAll(INLINE)) {
    const [tok] = m;
    const at = m.index ?? 0;
    if (at > last) nodes.push(text.slice(last, at));
    const key = `${keyBase}-${k++}`;
    if (m[1]) {
      nodes.push(<code key={key} className="font-data text-[0.88em] bg-ash px-1 py-0.5 rounded-[2px]">{tok.slice(1, -1)}</code>);
    } else if (m[2]) {
      nodes.push(<strong key={key} className="font-medium text-ink">{renderInline(tok.slice(2, -2), ctx, key)}</strong>);
    } else if (m[3]) {
      const lm = /^\[([^\]]+)\]\(([^)\s]+)\)$/.exec(tok);
      const target = lm ? resolveHref(lm[2], ctx) : null;
      nodes.push(
        lm && target ? (
          <a key={key} href={target.href} className="text-blue hover:underline underline-offset-4" target={target.href.startsWith("#") ? undefined : "_blank"} rel="noopener noreferrer">
            {renderInline(lm[1], ctx, key)}
          </a>
        ) : (
          tok
        ),
      );
    } else if (m[4] && RULE_ID.test(tok)) {
      nodes.push(<Link key={key} href={`/${ctx.locale}/rules/${tok}`} className="font-data text-[0.92em] text-blue hover:underline underline-offset-4">{tok}</Link>);
    } else if (m[5]) {
      nodes.push(<a key={key} href={tok} className="text-blue hover:underline underline-offset-4 break-all" target="_blank" rel="noopener noreferrer">{tok}</a>);
    } else if (m[6]) {
      nodes.push(<em key={key}>{renderInline(tok.slice(1, -1), ctx, key)}</em>);
    } else {
      nodes.push(tok);
    }
    last = at + tok.length;
  }
  if (last < text.length) nodes.push(text.slice(last));
  return nodes;
}

function splitRow(line: string): string[] {
  return line.trim().replace(/^\|/, "").replace(/\|$/, "").split(/(?<!\\)\|/).map((c) => c.trim().replace(/\\\|/g, "|"));
}

const TABLE_SEP = /^\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/;
const LIST_ITEM = /^(\s*)([-*+]|\d+\.)\s+(.*)$/;

/** Render a Markdown document. The first level-1 heading is dropped: the page supplies the title. */
export function renderMarkdown(source: string, ctx: Ctx): ReactNode[] {
  const lines = source.replace(/\r\n/g, "\n").split("\n");
  const out: ReactNode[] = [];
  let i = 0;
  let droppedTitle = false;
  const key = () => `b-${out.length}`;

  while (i < lines.length) {
    const line = lines[i];
    if (/^\s*$/.test(line)) { i++; continue; }

    if (/^```/.test(line)) {
      const body: string[] = [];
      i++;
      while (i < lines.length && !/^```/.test(lines[i])) body.push(lines[i++]);
      i++;
      out.push(<pre key={key()} className="font-data text-[12px] leading-[1.6] bg-ash border border-fog p-4 overflow-x-auto my-5">{body.join("\n")}</pre>);
      continue;
    }

    const h = /^(#{1,6})\s+(.*)$/.exec(line);
    if (h) {
      i++;
      const level = h[1].length;
      if (level === 1 && !droppedTitle) { droppedTitle = true; continue; }
      const cls = level <= 2 ? "mt-12 mb-4 text-[22px] text-ink" : level === 3 ? "mt-8 mb-3 text-[17px] text-ink" : "mt-6 mb-2 text-[15px] text-ink";
      const Tag = (level <= 2 ? "h2" : level === 3 ? "h3" : "h4") as "h2" | "h3" | "h4";
      out.push(<Tag key={key()} className={cls}>{renderInline(h[2], ctx)}</Tag>);
      continue;
    }

    if (/^\s*(-{3,}|\*{3,})\s*$/.test(line)) { i++; out.push(<hr key={key()} className="my-8 border-fog" />); continue; }

    if (line.trim().startsWith("|") && i + 1 < lines.length && TABLE_SEP.test(lines[i + 1])) {
      const head = splitRow(line);
      i += 2;
      const rows: string[][] = [];
      while (i < lines.length && lines[i].trim().startsWith("|")) rows.push(splitRow(lines[i++]));
      out.push(
        <div key={key()} className="my-6 overflow-x-auto">
          <table className="w-full text-left border-t border-fog text-[12.5px] min-w-[560px]">
            <thead>
              <tr className="border-b border-fog">
                {head.map((c, ci) => <th key={ci} className="py-2.5 pr-4 font-data text-[10px] uppercase tracking-[0.06em] text-mist font-normal align-bottom">{renderInline(c, ctx)}</th>)}
              </tr>
            </thead>
            <tbody>
              {rows.map((r, ri) => (
                <tr key={ri} className="border-b border-fog align-top">
                  {r.map((c, ci) => <td key={ci} className="py-2.5 pr-4 leading-[1.55] text-graphite">{renderInline(c, ctx, `t${ri}-${ci}`)}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>,
      );
      continue;
    }

    if (/^\s*>/.test(line)) {
      const body: string[] = [];
      while (i < lines.length && /^\s*>/.test(lines[i])) body.push(lines[i++].replace(/^\s*>\s?/, ""));
      out.push(
        <blockquote key={key()} className="my-5 border-l-2 border-navy pl-4 text-[14px] leading-[1.7] text-graphite">
          {renderMarkdown(body.join("\n"), { ...ctx })}
        </blockquote>,
      );
      continue;
    }

    if (LIST_ITEM.test(line)) {
      const items: { depth: number; ordered: boolean; text: string }[] = [];
      while (i < lines.length && (LIST_ITEM.test(lines[i]) || (/^\s{2,}\S/.test(lines[i]) && items.length > 0))) {
        const m = LIST_ITEM.exec(lines[i]);
        if (m) items.push({ depth: Math.floor(m[1].length / 2), ordered: /\d/.test(m[2]), text: m[3] });
        else items[items.length - 1].text += ` ${lines[i].trim()}`;
        i++;
      }
      const ordered = items[0]?.ordered ?? false;
      const List = (ordered ? "ol" : "ul") as "ol" | "ul";
      out.push(
        <List key={key()} className={`my-4 flex flex-col gap-1.5 text-[14px] leading-[1.65] text-graphite ${ordered ? "list-decimal" : "list-disc"} pl-5`}>
          {items.map((it, ii) => <li key={ii} style={{ marginLeft: `${it.depth * 1.25}rem` }}>{renderInline(it.text, ctx, `l${ii}`)}</li>)}
        </List>,
      );
      continue;
    }

    const para: string[] = [];
    while (i < lines.length && !/^\s*$/.test(lines[i]) && !/^(#{1,6}\s|```|\s*>|\s*(-{3,}|\*{3,})\s*$)/.test(lines[i]) && !LIST_ITEM.test(lines[i]) && !lines[i].trim().startsWith("|")) {
      para.push(lines[i++].trim());
    }
    if (para.length === 0) { para.push(lines[i++].trim()); }
    out.push(<p key={key()} className="my-4 text-[14.5px] leading-[1.75] text-graphite">{renderInline(para.join(" "), ctx)}</p>);
  }
  return out;
}
