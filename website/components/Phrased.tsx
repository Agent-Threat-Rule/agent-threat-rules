import { Children, Fragment, cloneElement, isValidElement, type ReactElement, type ReactNode } from "react";
import { hasChinese, phrases } from "@/lib/phrase";

// Wraps a server-rendered tree so Chinese text only breaks between words
// (see lib/phrase.ts). It rewrites string children of host elements and the
// children passed to components; text a component builds from other props is
// out of reach, so such components wrap their own output. Mark a subtree with
// data-nophrase to leave it untouched.

const SKIP = new Set(["code", "pre", "kbd", "samp", "script", "style", "textarea", "option", "title", "svg"]);

type AnyProps = { children?: ReactNode; "data-nophrase"?: unknown };

function phrased(text: string): ReactNode {
  if (!hasChinese(text)) return text;
  const parts = phrases(text);
  return (
    <span className="phr" data-nophrase="">
      {parts.map((p, i) => (
        <Fragment key={i}>
          {i > 0 && <wbr />}
          {p}
        </Fragment>
      ))}
    </span>
  );
}

function walk(node: ReactNode): ReactNode {
  if (typeof node === "string") return phrased(node);
  if (Array.isArray(node)) return Children.map(node, walk);
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
