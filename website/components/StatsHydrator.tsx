"use client";

import { useEffect } from "react";

const GITHUB_RAW =
  "https://raw.githubusercontent.com/Agent-Threat-Rule/agent-threat-rules/main/data";

/**
 * Client component that fetches latest stats from GitHub on mount
 * and dispatches a custom event. CountUp components listen for this
 * event and update their targets if the live value differs.
 *
 * Drop this anywhere in the page — it renders nothing.
 */
export function StatsHydrator() {
  useEffect(() => {
    // Mark document as JS-ready so reveal animations work.
    // Without this class, CSS shows all content visible (for crawlers/noscript).
    document.documentElement.classList.add("js-ready");

    let cancelled = false;

    async function hydrate() {
      try {
        const statsRes = await fetch(`${GITHUB_RAW}/stats.json`, { cache: "no-store" })
          .then(r => r.ok ? r.json() : null)
          .catch(() => null);

        if (cancelled) return;

        const live: Record<string, number> = {};

        // Live rule count + categories from stats.json
        if (statsRes?.rules) {
          live.ruleCount = statsRes.rules.total;
          live.categoryCount = statsRes.rules.categories;
        }

        // Wild-scan figures are deliberately NOT hydrated. The wild scan is a
        // frozen one-off artifact from 2026-04-13, not a live counter, and the
        // remote mega-scan-report.json / stats.json ecosystem block still carry
        // the withdrawn subset totals. The build-time values from
        // data/full-scan-v2-2026-04-14.json are the citable ones — leave them.

        // Benchmark figures are deliberately NOT hydrated either. A recall is
        // only honest next to its lane: the build reads both from the same
        // measurement file (lib/stats.ts, lib/recall.ts), and the site is rebuilt
        // whenever data/ changes on main. Hydrating a hunt figure from the old
        // report files could put it beside an enforce figure from another run.

        if (Object.keys(live).length > 0) {
          window.dispatchEvent(new CustomEvent("atr:live-stats", { detail: live }));
        }
      } catch {
        // Silent fail — build-time data stays
      }
    }

    hydrate();
    return () => { cancelled = true; };
  }, []);

  return null;
}
