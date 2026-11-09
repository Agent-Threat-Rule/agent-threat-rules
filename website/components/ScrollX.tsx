"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";

const FADE = { paper: "from-paper", ash: "from-ash" } as const;

/**
 * Horizontal scroll container for code and wide tables. The page itself never
 * scrolls sideways: only this box does. When its content is wider than the
 * box, a soft fade sits on the right edge and a one-line hint appears under
 * it, and both go away once the reader reaches the end.
 */
export function ScrollX({
  zh,
  className = "",
  tone = "paper",
  children,
}: {
  zh: boolean;
  className?: string;
  /** Background behind the content, so the fade blends into it. */
  tone?: keyof typeof FADE;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [more, setMore] = useState(false);
  const [wide, setWide] = useState(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const check = () => {
      const overflow = el.scrollWidth - el.clientWidth > 2;
      setWide(overflow);
      setMore(overflow && el.scrollLeft + el.clientWidth < el.scrollWidth - 2);
    };
    check();
    el.addEventListener("scroll", check, { passive: true });
    const ro = new ResizeObserver(check);
    ro.observe(el);
    return () => {
      el.removeEventListener("scroll", check);
      ro.disconnect();
    };
  }, []);

  return (
    <div className="min-w-0" data-scrollx="">
      <div className="relative">
        <div ref={ref} className={`overflow-x-auto ${className}`}>
          {children}
        </div>
        <span
          aria-hidden="true"
          className={`pointer-events-none absolute top-0 right-0 bottom-0 w-10 bg-gradient-to-l ${FADE[tone]} to-transparent transition-opacity duration-200 ${more ? "opacity-100" : "opacity-0"}`}
        />
      </div>
      {wide && <div className="mt-1.5 text-[12px] text-mist md:hidden">{zh ? "左右滑動看完整內容" : "Scroll sideways to see all of it"}</div>}
    </div>
  );
}
