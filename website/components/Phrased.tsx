import { Children, Fragment, cloneElement, isValidElement, type ReactElement, type ReactNode } from "react";
import { hasChinese, phrases } from "@/lib/phrase";

// Wraps a server-rendered tree so Chinese text only breaks between words
// (see lib/phrase.ts). It rewrites string children of host elements and the
// children passed to components; text a component builds from other props is
// out of reach, so such components wrap their own output. Mark a subtree with
// data-nophrase to leave it untouched.

const TAIL_NOWRAP = 14;

const SKIP = new Set(["code", "pre", "kbd", "samp", "script", "style", "textarea", "option", "title", "svg"]);

type AnyProps = { children?: ReactNode; "data-nophrase"?: unknown };

function phrased(text: string): ReactNode {
  if (!hasChinese(text)) return text;
  const parts = phrases(text);
  const last = parts.length - 1;
  return (
    <span className="phr" data-nophrase="">
      {parts.map((p, i) => (
        <Fragment key={i}>
          {i > 0 && <wbr />}
          {/* The tail may hold a space ("MIT 授權"); keep it on one line. */}
          {i === last && i > 0 && p.trim().length <= TAIL_NOWRAP ? <span className="whitespace-nowrap">{p}</span> : p}
        </Fragment>
      ))}
    </span>
  );
}

/** Plain text inside a node, for measuring how long an inline element is. */
function textOf(node: ReactNode): string {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(textOf).join("");
  if (isValidElement(node)) return textOf((node as ReactElement<AnyProps>).props.children);
  return "";
}

/**
 * A block that ends with a short inline element followed by one or two
 * characters ("...寫在 <code>x</code> 裡。") would leave those characters alone
 * on the last line; keep them on the same line as the element.
 */
function keepEndTogether(children: ReactNode[]): ReactNode[] {
  const n = children.length;
  const last = children[n - 1];
  const prev = children[n - 2];
  if (n < 2 || typeof last !== "string" || !isValidElement(prev)) return children;
  if (!hasChinese(last) || last.trim().length > 3 || textOf(prev).length > 20) return children;
  return [
    ...children.slice(0, n - 2),
    <span key="end" className="whitespace-nowrap" data-nophrase="">
      {prev}
      {last}
    </span>,
  ];
}

function walk(node: ReactNode): ReactNode {
  if (typeof node === "string") return phrased(node);
  if (Array.isArray(node)) return Children.map(keepEndTogether(node), walk);
  if (!isValidElement(node)) return node;
  const el = node as ReactElement<AnyProps>;
  if (typeof el.type === "string" && SKIP.has(el.type)) return el;
  const { children } = el.props;
  if (el.props["data-nophrase"] !== undefined || children === undefined || typeof children === "function") return el;
  return cloneElement(el, undefined, walk(children));
}

export default function Phrased({ children }: { children: ReactNode }) {
  return <>{walk(children)}</>;
}
