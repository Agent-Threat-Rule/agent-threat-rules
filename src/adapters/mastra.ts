/**
 * Mastra input processor for Agent Threat Rules (ATR).
 *
 * A drop-in Mastra `Processor` that evaluates incoming user input against the
 * ATR rule set and aborts the run when a rule at or above a configured severity
 * matches. ATR is an open detection standard for AI-agent attacks (like Sigma,
 * but for prompt injection and related input-borne threats).
 *
 *   import { Agent } from "@mastra/core/agent";
 *   import { ATRProcessor } from "agent-threat-rules/mastra";
 *
 *   const agent = new Agent({
 *     name: "guarded",
 *     model,
 *     inputProcessors: [new ATRProcessor()],
 *   });
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

const DEFAULT_BLOCK_SEVERITIES: readonly string[] = ["critical", "high"];

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

export interface ATRProcessorOptions {
  /** ATR match severities that abort the run. Lower severities pass through. Defaults to ["critical", "high"]. */
  readonly blockSeverities?: readonly string[];
  /** Directory of ATR rule YAML files. Omit to use the rules bundled with this package. */
  readonly rulesDir?: string;
}

/**
 * Mastra input processor that blocks input matching Agent Threat Rules.
 */
export class ATRProcessor {
  readonly id = "atr" as const;
  readonly name = "Agent Threat Rules";

  private readonly engine: ATREngine;
  private readonly blockSeverities: ReadonlySet<string>;
  private loadPromise: Promise<number> | null = null;

  constructor(options: ATRProcessorOptions = {}) {
    this.engine = new ATREngine(options.rulesDir ? { rulesDir: options.rulesDir } : {});
    this.blockSeverities = new Set(
      (options.blockSeverities ?? DEFAULT_BLOCK_SEVERITIES).map((severity) => severity.toLowerCase()),
    );
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
      const blocking = matches.filter((match) => this.blockSeverities.has(match.rule.severity.toLowerCase()));
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
