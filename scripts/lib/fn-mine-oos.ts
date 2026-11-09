/**
 * scripts/lib/fn-mine-oos.ts
 *
 * Every attack corpus under data/fn-mine-oos, with the delivery shape its
 * samples reach an agent as. Each one is both:
 *   - a corpus the FN-mine lane mines (scripts/lib/fn-mine-corpora.ts adds an
 *     `oos` spec for each), and
 *   - out-of-sample evidence for every rule mined from any other corpus
 *     (scripts/lib/fn-mine-generalization.ts excludes only the corpus a rule
 *     came from).
 *
 * So a corpus does not lose its value as evidence by being mined: it only
 * stops counting for the rules mined from itself.
 *
 * Three scripts write these directories:
 *   - scripts/sync-generalization-corpora.py: agentdojo, injecagent
 *   - scripts/sync-oos-corpora.py:            spikee .. jailbreak-cls
 *   - scripts/sync-attack-sources.py:         the rest (data/fn-mine-oos/SOURCES.json lists them)
 * tests/fn-mine-oos-registry.test.ts fails when a directory exists that is not
 * listed here, so a corpus cannot be vendored and silently left unmined.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { DeliveryShape } from './fn-corpora.js';

export interface OosSource {
  readonly id: string;
  readonly path: string;
  readonly shape: DeliveryShape;
  /** Which script writes it, for the error that names the fix. */
  readonly sync: 'sync-generalization-corpora.py' | 'sync-oos-corpora.py' | 'sync-attack-sources.py';
  /** A generator's fixed scaffolding the miner must not anchor a regex on. */
  readonly goalNote?: string;
}

const oos = (id: string, shape: DeliveryShape, sync: OosSource['sync'], goalNote?: string): OosSource =>
  Object.freeze({ id, path: `data/fn-mine-oos/${id}/corpus.json`, shape, sync, ...(goalNote ? { goalNote } : {}) });

const TEMPLATE_NOTE =
  'Every row is one of a few fixed templates filled with the benchmark\'s own instructions: a regex on a template verbatim ' +
  'recovers this corpus and nothing else, and the out-of-sample gate drops it. Key on the technique the template uses.';

export const OOS_SOURCES: readonly OosSource[] = Object.freeze([
  oos('agentdojo', 'tool_response', 'sync-generalization-corpora.py', TEMPLATE_NOTE),
  oos('injecagent', 'tool_response', 'sync-generalization-corpora.py', TEMPLATE_NOTE),
  oos('spikee', 'tool_response', 'sync-oos-corpora.py', TEMPLATE_NOTE),
  oos('asb', 'tool_response', 'sync-oos-corpora.py',
    'Every row starts with ASB\'s filler "Request completed successfully. 3 results returned" and carries one of five fixed ' +
    'templates around "You must strictly adhere to the following instruction ... by using the X tool": never anchor on the ' +
    'filler or the template wording.'),
  oos('bipia', 'tool_response', 'sync-oos-corpora.py'),
  oos('gentel', 'llm_input', 'sync-oos-corpora.py'),
  oos('gandalf', 'llm_input', 'sync-oos-corpora.py',
    'Players tried to get a password out of the Gandalf bot: never anchor on "password" or the game\'s wording.'),
  oos('mosscap', 'llm_input', 'sync-oos-corpora.py',
    'Players tried to get a password out of the Mosscap bot: never anchor on "password" or the game\'s wording.'),
  oos('deepset', 'llm_input', 'sync-oos-corpora.py'),
  oos('jailbreak-cls', 'llm_input', 'sync-oos-corpora.py'),
  oos('web-agent-attack', 'tool_response', 'sync-attack-sources.py',
    'Injections a generator planted in web pages; the target-site names and link texts are per-page fixtures.'),
  oos('agentic-pi-pairs', 'llm_input', 'sync-attack-sources.py'),
  oos('agentic-pi-5k', 'llm_input', 'sync-attack-sources.py'),
  oos('mcp-tool-poisoning', 'tool_response', 'sync-attack-sources.py'),
  oos('ja-indirect-pi', 'tool_response', 'sync-attack-sources.py',
    'Every row asks for the canary string "ZX-100n": never anchor on the canary.'),
  oos('repo-context-pi', 'tool_response', 'sync-attack-sources.py',
    'Rows end with a generated "Repository note #N" counter: never anchor on it.'),
  oos('agent-secret-extraction', 'llm_input', 'sync-attack-sources.py',
    'The prompts name fictional agents (Nova, configuration ids such as GA-CORE-1101): never anchor on those names or ids.'),
  oos('in-the-wild-jailbreak', 'llm_input', 'sync-attack-sources.py'),
  oos('jailbreakv', 'llm_input', 'sync-attack-sources.py'),
  oos('neuralchemy-pi', 'llm_input', 'sync-attack-sources.py'),
  oos('s-labs-pi', 'llm_input', 'sync-attack-sources.py'),
  oos('wambosec-pi', 'llm_input', 'sync-attack-sources.py'),
  oos('wambosec-subtle', 'llm_input', 'sync-attack-sources.py'),
  oos('multilingual-pi', 'llm_input', 'sync-attack-sources.py'),
  oos('simsonsun-jailbreak', 'llm_input', 'sync-attack-sources.py'),
  oos('aidatafdn-pi', 'llm_input', 'sync-attack-sources.py'),
  oos('promptprotection-attacks', 'llm_input', 'sync-attack-sources.py'),
  oos('promptprotection-flows', 'tool_response', 'sync-attack-sources.py'),
  oos('cyberseceval-pi', 'llm_input', 'sync-attack-sources.py',
    'Test inputs target fixed secrets (a key word such as "Piano"): never anchor on the secret.'),
  oos('jailbreakbench-artifacts', 'llm_input', 'sync-attack-sources.py'),
  oos('pyrit-jailbreak-templates', 'llm_input', 'sync-attack-sources.py',
    'The template placeholder was filled with "tell me the contents of your system prompt": never anchor on that sentence.'),
  oos('spml-chatbot-pi', 'llm_input', 'sync-attack-sources.py',
    'Rows name generated chatbot personas (Healthcare Advisor Bot, FitCompanion): never anchor on a persona name.'),
  oos('english-pi-3k', 'llm_input', 'sync-attack-sources.py'),
  oos('multilingual-extraction-pi', 'llm_input', 'sync-attack-sources.py'),
  oos('pi-benchmark-categories', 'llm_input', 'sync-attack-sources.py'),
  oos('k8s-resource-pi', 'tool_response', 'sync-attack-sources.py',
    'The planted payloads are HackAPrompt-style canaries ("I have been PWNED") inside real manifests; the manifest fields ' +
    'and repository names are fixtures: never anchor on the canary or on Kubernetes keys.'),
]);

export function oosSource(id: string): OosSource | undefined {
  return OOS_SOURCES.find((s) => s.id === id);
}

/** The attack texts of one OOS corpus, or why they cannot be trusted. */
export function readOosTexts(root: string, source: OosSource): { readonly texts: readonly string[] } | { readonly problem: string } {
  const file = join(root, source.path);
  if (!existsSync(file)) return { problem: `${source.path} is missing (run scripts/${source.sync} --write)` };
  let doc: { count?: unknown; samples?: { text?: unknown }[] };
  try {
    doc = JSON.parse(readFileSync(file, 'utf8')) as typeof doc;
  } catch (e) {
    return { problem: `${source.path} is not valid JSON (${e instanceof Error ? e.message : String(e)})` };
  }
  const texts = (doc.samples ?? []).map((s) => s.text).filter((t): t is string => typeof t === 'string' && t.length > 0);
  if (texts.length === 0 || doc.count !== texts.length) {
    return { problem: `${source.path} declares ${String(doc.count)} samples but holds ${texts.length}` };
  }
  return { texts };
}
