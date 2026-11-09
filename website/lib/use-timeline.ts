"use client";

import { useEffect, useState, type RefObject } from "react";
import { useReducedMotion } from "@/lib/use-reduced-motion";

/**
 * A looping clock for the explainer animations, in milliseconds. It runs only
 * while the element is on screen; with reduced motion it stays at `still`,
 * a moment where everything has been drawn.
 */
export function useTimeline(ref: RefObject<HTMLElement | null>, total: number, still: number) {
  const [t, setT] = useState(0);
  const reduced = useReducedMotion();

  useEffect(() => {
    const el = ref.current;
    if (!el || reduced) return;
    let raf = 0;
    let running = false;
    let clock = 0;
    let last = 0;
    let shown = 0;
    const frame = (ts: number) => {
      clock = (clock + (last ? Math.min(250, ts - last) : 16)) % total;
      last = ts;
      if (ts - shown > 40) {
        shown = ts;
        setT(clock);
      }
      raf = requestAnimationFrame(frame);
    };
    const io = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting && !running) {
          running = true;
          last = 0;
          raf = requestAnimationFrame(frame);
        } else if (!entry.isIntersecting && running) {
          running = false;
          cancelAnimationFrame(raf);
        }
      },
      { threshold: 0.15 },
    );
    io.observe(el);
    return () => {
      io.disconnect();
      cancelAnimationFrame(raf);
    };
  }, [ref, total, reduced]);

  return reduced ? still : t;
}
