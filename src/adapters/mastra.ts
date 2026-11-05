/**
 * Mastra input processor for Agent Threat Rules (ATR).
 *
 * A drop-in Mastra `Processor` that evaluates incoming user input against the
 * ATR rule set and reports what matched. ATR is an open detection standard for
 * AI-agent attacks (like Sigma, but for prompt injection and related
 * input-borne threats).
 *
 *   import { Agent } from "@mastra/core/agent";
 *   import { ATRProcessor } from "agent-threat-rules/mastra";
 *
 *   const agent = new Agent({
 *     name: "guarded",
 *     model,
 *     inputProcessors: [new ATRProcessor()],                   // report only
 *     // inputProcessors: [new ATRProcessor({ blocking: true })], // may abort
 *   });
 *
 * BLOCKING IS OFF BY DEFAULT. Without `blocking: true` the processor never
 * calls abort(); every match is handed to `onDetection` (default: one line on
 * console.warn) and the input passes through unchanged. With it, the run is
 * aborted only on a blocking-eligible match (src/enforcement.ts,
 * isBlockingEligible): a live maturity: stable rule at high or critical
 * severity. This processor used to abort by default on any hunt-lane match at
 * critical or high — experimental rules included — with no way to turn that
 * off short of `blockSeverities: []`. Detection still runs in the hunt lane, so
 * what is reported did not narrow.
 *
 * The Mastra `Processor` contract is captured structurally (via generics), so
 * this module adds NO dependency on `@mastra/core` -- the package stays
 * decoupled from Mastra's release cadence. `@mastra/core` is an optional peer:
 * install it in the consuming app. Conformance is verified against the real
 * @mastra/core types in the test suite.
 *
 * @module agent-threat-rules/mastra
 */

import { ATREngine } from "../engine.js";
import type { ATRMatch, ATRSeverity } from "../types.js";
import {
  BLOCKING_SEVERITIES,
  blockingFromConfig,
  blockingMatches,
  parseBlockingSeverity,
} from "../enforcement.js";

/** Structural shape of a Mastra message -- only the text-bearing fields we read. */
interface MastraLikeMessage {
  content: {
    parts?: ReadonlyArray<{ type: string; text?: string }>;
    content?: string;
  };
}

/** Structural shape of the argument Mastra passes to a processor's processInput. */
interface MastraProcessInputArgs<M extends MastraLikeMessage> {
  messages: M[];
  abort: (reason?: string) => never;
}

/** What the processor reports for one message that matched at least one rule. */
export interface ATRDetectionReport {
  /** Every match, in the hunt lane, whatever its maturity or severity. */
  readonly matches: readonly ATRMatch[];
  /** The matches that may abort the run (empty unless blocking is on). */
  readonly blocking: readonly ATRMatch[];
  /** Whether this processor is allowed to abort. */
  readonly blockingEnabled: boolean;
}

export interface ATRProcessorOptions {
  /**
   * Allow the processor to abort the run. OFF BY DEFAULT. A non-boolean throws:
   * `blocking: "false"` would otherwise be truthy.
   */
  readonly blocking?: boolean;
  /**
   * Severities that may abort the run once blocking is on. Must be a subset of
   * ["critical", "high"] — a lower severity throws, because only high and
   * critical matches from stable rules may block. Defaults to both. An empty
   * list means nothing aborts.
   */
  readonly blockSeverities?: readonly string[];
  /** Directory of ATR rule YAML files. Omit to use the rules bundled with this package. */
  readonly rulesDir?: string;
  /**
   * Called once per message that matched any rule. Defaults to a one-line
   * console.warn, so report-only mode is not silent.
   */
  readonly onDetection?: (report: ATRDetectionReport) => void;
}

/**
 * Validate blockSeverities: each entry must be high or critical.
 *
 * @throws TypeError naming the offending value.
 */
function resolveBlockSeverities(requested: readonly string[] | undefined): readonly ATRSeverity[] {
  if (requested === undefined) return BLOCKING_SEVERITIES;
  const parsed = requested.map((severity) => {
    const value = typeof severity === "string" ? parseBlockingSeverity(severity) : null;
    if (value === null) {
      throw new TypeError(
        `Invalid blockSeverities entry ${JSON.stringify(severity)}. Expected a subset of ` +
          `[${BLOCKING_SEVERITIES.join(", ")}]: only high and critical matches from ` +
          `maturity: stable rules may block. Lower severities are still reported.`,
      );
    }
    return value;
  });
  return Object.freeze([...new Set(parsed)]);
}

function defaultReport(report: ATRDetectionReport): void {
  const ids = report.matches.map((match) => match.rule.id).join(", ");
  const mode = report.blockingEnabled ? `${report.blocking.length} blocking-eligible` : "report only";
  console.warn(`[atr] input matched ${report.matches.length} rule(s) [${ids}] (${mode})`);
}

/**
 * Mastra input processor that blocks input matching Agent Threat Rules.
 */
export class ATRProcessor {
  readonly id = "atr" as const;
  readonly name = "Agent Threat Rules";

  private readonly engine: ATREngine;
  private readonly blocking: boolean;
  private readonly blockSeverities: readonly ATRSeverity[];
  private readonly onDetection: (report: ATRDetectionReport) => void;
  private loadPromise: Promise<number> | null = null;

  constructor(options: ATRProcessorOptions = {}) {
    this.blocking = blockingFromConfig(options.blocking);
    this.blockSeverities = resolveBlockSeverities(options.blockSeverities);
    this.onDetection = options.onDetection ?? defaultReport;
    this.engine = new ATREngine(options.rulesDir ? { rulesDir: options.rulesDir } : {});
  }

  /** Is this processor allowed to abort the run? */
  isBlocking(): boolean {
    return this.blocking;
  }

  /** Load rules exactly once, even under concurrent first calls. */
  private ensureLoaded(): Promise<number> {
    if (this.loadPromise === null) {
      this.loadPromise = this.engine.loadRules();
    }
    return this.loadPromise;
  }

  private static extractText(message: MastraLikeMessage): string {
    let text = "";
    for (const part of message.content.parts ?? []) {
      if (part.type === "text" && typeof part.text === "string") {
        text += part.text + " ";
      }
    }
    if (!text.trim() && typeof message.content.content === "string") {
      text = message.content.content;
    }
    return text.trim();
  }

  async processInput<M extends MastraLikeMessage>(args: MastraProcessInputArgs<M>): Promise<M[]> {
    const { messages, abort } = args;
    await this.ensureLoaded();

    for (const message of messages) {
      const text = ATRProcessor.extractText(message);
      if (!text) continue;

      const matches = this.engine.evaluate({
        type: "llm_input",
        timestamp: new Date().toISOString(),
        content: text,
      });
      if (matches.length === 0) continue;
      // evaluate() is the synchronous path: no model decides a match here, and
      // the engine is in the hunt lane, so an unconfirmed confirm-rule cannot
      // block (detectionLane defaults to hunt).
      const blocking = this.blocking
        ? blockingMatches(matches, { severities: this.blockSeverities })
        : [];
      this.onDetection({ matches, blocking, blockingEnabled: this.blocking });
      if (blocking.length > 0) {
        const ruleIds = blocking.map((match) => match.rule.id).join(", ");
        const severities = [...new Set(blocking.map((match) => match.rule.severity))].join("/");
        abort(
          `Input blocked by Agent Threat Rules: matched ${blocking.length} rule(s) [${ruleIds}] (severity: ${severities}).`,
        );
      }
    }

    return messages;
  }
}
