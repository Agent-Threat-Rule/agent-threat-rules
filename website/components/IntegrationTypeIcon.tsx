import type { IntegrationType } from "@/lib/adopters";

/**
 * Minimal stroke icons for the ADOPTERS.md integration-type enum, so an
 * engineer scanning the ecosystem page can read the SHAPE of each
 * integration at a glance (run the engine? import the rules? convert the
 * format?) before reading any prose. Pure inline SVG — no icon library,
 * no client JS.
 */

const STROKE = {
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.5,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
};

function pathsFor(type: IntegrationType): React.ReactNode {
  switch (type) {
    case "engine":
      // CPU chip: die + pins
      return (
        <>
          <rect x="4.5" y="4.5" width="7" height="7" rx="1" {...STROKE} />
          <path d="M6.5 4.5v-2M9.5 4.5v-2M6.5 13.5v-2M9.5 13.5v-2M4.5 6.5h-2M4.5 9.5h-2M13.5 6.5h-2M13.5 9.5h-2" {...STROKE} />
        </>
      );
    case "rule-import":
      // Arrow down into a tray
      return (
        <>
          <path d="M8 2.5v7M5.5 7L8 9.5 10.5 7" {...STROKE} />
          <path d="M2.5 10.5v2a1 1 0 0 0 1 1h9a1 1 0 0 0 1-1v-2" {...STROKE} />
        </>
      );
    case "category-subset":
      // Funnel
      return (
        <path d="M2.5 3.5h11L9.5 8.5v4l-3 1v-5L2.5 3.5Z" {...STROKE} />
      );
    case "adapter":
      // Plug
      return (
        <>
          <path d="M5.5 2.5v3M10.5 2.5v3" {...STROKE} />
          <path d="M4 5.5h8v2.5a4 4 0 0 1-8 0V5.5Z" {...STROKE} />
          <path d="M8 12v2" {...STROKE} />
        </>
      );
    case "reference":
      // Open book
      return (
        <path d="M8 3.5c-1.2-1-3.2-1-5.5-.7v9.7c2.3-.3 4.3-.3 5.5.7 1.2-1 3.2-1 5.5-.7V2.8c-2.3-.3-4.3-.3-5.5.7Zm0 0v10" {...STROKE} />
      );
    case "sidecar-proxy":
      // Shield beside a service box
      return (
        <>
          <rect x="2" y="4.5" width="6" height="7" rx="1" {...STROKE} />
          <path d="M11.5 4l2.5 1v3c0 2-1.2 3.3-2.5 4-1.3-.7-2.5-2-2.5-4V5l2.5-1Z" {...STROKE} />
        </>
      );
    default:
      // "other" — node with link
      return (
        <>
          <circle cx="8" cy="8" r="2.5" {...STROKE} />
          <path d="M10.5 8h3M2.5 8h3" {...STROKE} />
        </>
      );
  }
}

/** Human label for an integration type. */
export function integrationTypeLabel(
  type: IntegrationType,
  locale: "en" | "zh",
): string {
  const labels: Record<IntegrationType, { en: string; zh: string }> = {
    engine: { en: "engine", zh: "引擎實作" },
    "rule-import": { en: "rule-import", zh: "規則匯入" },
    "category-subset": { en: "category-subset", zh: "類別子集" },
    adapter: { en: "adapter", zh: "格式轉接" },
    reference: { en: "reference", zh: "文件引用" },
    "sidecar-proxy": { en: "sidecar-proxy", zh: "旁路代理" },
    other: { en: "other", zh: "其他" },
  };
  return labels[type][locale];
}

/** One-line, engineer-facing meaning of each integration shape. */
export function integrationTypeHint(
  type: IntegrationType,
  locale: "en" | "zh",
): string {
  const hints: Record<IntegrationType, { en: string; zh: string }> = {
    engine: {
      en: "Builds its own ATR engine that conforms to the spec",
      zh: "自己實作一個符合規格的 ATR 引擎",
    },
    "rule-import": {
      en: "Runs the ATR rules inside its own scanner",
      zh: "把 ATR 規則放進自己的掃描器裡跑",
    },
    "category-subset": {
      en: "Takes in some ATR categories, not all",
      zh: "只匯入部分 ATR 類別",
    },
    adapter: {
      en: "Converts between ATR and another rule format",
      zh: "在 ATR 和其他規則格式之間互轉",
    },
    reference: {
      en: "Cites ATR in a catalogue, a taxonomy or its docs",
      zh: "在目錄、分類法或文件裡引用 ATR",
    },
    "sidecar-proxy": {
      en: "Runs ATR beside the agent, as a proxy or callback layer",
      zh: "在 agent 旁邊跑 ATR，當代理或回呼層",
    },
    other: {
      en: "An integration that fits none of the types above",
      zh: "不屬於以上任何一種的整合",
    },
  };
  return hints[type][locale];
}

export function IntegrationTypeIcon({
  type,
  size = 16,
  className,
}: {
  type: IntegrationType;
  size?: number;
  className?: string;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      aria-hidden="true"
      className={className}
    >
      {pathsFor(type)}
    </svg>
  );
}
