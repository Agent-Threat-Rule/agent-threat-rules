"use client";

import { useEffect, useState, type RefObject } from "react";
import { useReducedMotion } from "@/lib/use-reduced-motion";

/**
 * Advances through `durations.length` steps, each held for its duration in
 * milliseconds, then wraps. Runs only while the element is on screen.
 * `initial` is the step the server renders, so the first paint is already
 * complete; with reduced motion the steps stay there. Changes happen a few
 * times a second at most; the motion itself is CSS transitions, so nothing
 * redraws per frame.
 */
export function useSteps(ref: RefObject<HTMLElement | null>, durations: ReadonlyArray<number>, paused = false, initial = 0) {
  const [step, setStep] = useState(initial);
  const [visible, setVisible] = useState(false);
  const reduced = useReducedMotion();

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const io = new IntersectionObserver(([entry]) => setVisible(entry.isIntersecting), { threshold: 0.2 });
    io.observe(el);
    return () => io.disconnect();
  }, [ref]);

  useEffect(() => {
    if (reduced || !visible || paused) return;
    const id = window.setTimeout(() => setStep((s) => (s + 1) % durations.length), durations[step]);
    return () => window.clearTimeout(id);
  }, [step, visible, paused, reduced, durations]);

  return [reduced ? initial || durations.length - 1 : step, setStep] as const;
}
