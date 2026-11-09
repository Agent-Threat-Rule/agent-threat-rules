"use client";

import { useEffect, useRef, useState } from "react";

export function TypedTerminal({ command = "npm install agent-threat-rules" }: { command?: string }) {
  const [displayed, setDisplayed] = useState("");
  const [done, setDone] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const started = useRef(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;

    // Respect prefers-reduced-motion
    const prefersReduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting && !started.current) {
          started.current = true;

          if (prefersReduced) {
            setDisplayed(command);
            setDone(true);
            observer.disconnect();
            return;
          }

          let i = 0;
          const id = setInterval(() => {
            i++;
            setDisplayed(command.slice(0, i));
            if (i >= command.length) {
              clearInterval(id);
              setDone(true);
            }
          }, 55);
          observer.disconnect();
        }
      },
      { threshold: 0.5 }
    );

    observer.observe(el);
    return () => observer.disconnect();
  }, [command]);

  return (
    <div
      ref={ref}
      className="font-data text-sm bg-[#0B0B0F] text-[#4ade80] px-6 py-4 border border-[#2A2A35] inline-block "
    >
      <span className="text-[#6B6B76]">$</span>{" "}
      <span>{displayed}</span>
      <span
        className={`inline-block w-[8px] h-[18px] bg-[#4ade80] ml-0.5 align-middle ${done ? "animate-pulse" : ""}`}
        style={{ opacity: displayed.length > 0 || done ? 1 : 0 }}
      />
    </div>
  );
}
