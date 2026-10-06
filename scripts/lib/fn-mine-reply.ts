/**
 * scripts/lib/fn-mine-reply.ts
 *
 * Reads the model's mining reply for the scheduled FN-mine lane
 * (scripts/fn-mine-llm.ts).
 *
 * The reply is asked to be pure JSON, and nearly always is. On 2026-10-06 one
 * PINT chunk came back with a trailing comma, JSON.parse threw inside the
 * mining loop, and the whole run died after an hour of coverage and mining:
 * the HackAPrompt survivor it had already gated was lost with it. One chunk's
 * bad reply is now that chunk's problem. The caller repairs what is safe to
 * repair, asks once more, and then skips the chunk; only a run in which no
 * chunk could be read fails, so a dead model still turns the job red.
 */

export interface MineCandidate {
  cluster: string;
  regex: string;
  category: string;
  rationale: string;
}

/** The first balanced top-level JSON object in `text`, markdown fences stripped. */
export function extractBalancedJson(text: string): string {
  let cleaned = text.trim();
  cleaned = cleaned.replace(/^```(?:json)?\s*\n?/i, '').replace(/\n?```\s*$/i, '');
  const firstBrace = cleaned.indexOf('{');
  if (firstBrace === -1) throw new Error('No JSON object opening brace found in LLM output');
  let depth = 0;
  let inString = false;
  let escape = false;
  let lastBrace = -1;
  for (let i = firstBrace; i < cleaned.length; i++) {
    const ch = cleaned[i];
    if (escape) { escape = false; continue; }
    if (inString) {
      if (ch === '\\') escape = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') { inString = true; continue; }
    if (ch === '{') depth++;
    else if (ch === '}') { depth--; if (depth === 0) { lastBrace = i; break; } }
  }
  if (lastBrace === -1) throw new Error('Unbalanced braces — no top-level JSON object closed');
  return cleaned.slice(firstBrace, lastBrace + 1);
}

/**
 * Drop each comma that is followed only by whitespace and then `}` or `]`,
 * outside strings. That is the slip the 2026-10-06 reply made, and removing
 * such a comma cannot change what any valid JSON means. Nothing else is
 * repaired: a reply broken another way is asked for again.
 */
export function stripTrailingCommas(json: string): string {
  let out = '';
  let inString = false;
  let escape = false;
  for (let i = 0; i < json.length; i++) {
    const ch = json[i];
    if (inString) {
      out += ch;
      if (escape) escape = false;
      else if (ch === '\\') escape = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') inString = true;
    if (ch === ',' && /^\s*[}\]]/.test(json.slice(i + 1))) continue;
    out += ch;
  }
  return out;
}

function isCandidate(c: unknown): c is MineCandidate {
  if (!c || typeof c !== 'object') return false;
  const o = c as Record<string, unknown>;
  return ['cluster', 'regex', 'category', 'rationale'].every((k) => typeof o[k] === 'string');
}

export interface ParsedReply {
  readonly candidates: MineCandidate[];
  /** Entries dropped because a field was missing or not a string. */
  readonly malformed: number;
}

/**
 * Parse a mining reply. Throws when the reply is not a JSON object with a
 * `candidates` array (absent counts as empty, the prompt's "nothing here").
 * Entries of the wrong shape are dropped and counted rather than handed to the
 * gate, which would throw on a non-string regex.
 */
export function parseMineReply(raw: string): ParsedReply {
  const json = extractBalancedJson(raw);
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    parsed = JSON.parse(stripTrailingCommas(json));
  }
  const list = (parsed as { candidates?: unknown }).candidates ?? [];
  if (!Array.isArray(list)) throw new Error('"candidates" is not an array');
  const candidates = list.filter(isCandidate);
  return { candidates, malformed: list.length - candidates.length };
}

export interface ChunkResult {
  readonly candidates: MineCandidate[];
  /** False when no reply for this chunk could be read, after the retry. */
  readonly read: boolean;
}

/**
 * Ask for one chunk's candidates, once more if the reply cannot be read.
 * `ask` is the model call; `warn` receives one line per unreadable reply.
 */
export async function mineChunkReply(
  label: string,
  ask: () => Promise<string>,
  warn: (line: string) => void,
  attempts = 2,
): Promise<ChunkResult> {
  for (let attempt = 1; attempt <= attempts; attempt++) {
    const raw = await ask();
    try {
      const reply = parseMineReply(raw);
      if (reply.malformed > 0) warn(`${label}: dropped ${reply.malformed} candidate(s) missing a string field`);
      return { candidates: reply.candidates, read: true };
    } catch (e) {
      const why = e instanceof Error ? e.message : String(e);
      const next = attempt < attempts ? 'asking again' : 'skipping this chunk';
      warn(`${label}: reply ${attempt} of ${attempts} is not usable JSON (${why}); ${next}`);
    }
  }
  return { candidates: [], read: false };
}

/**
 * A run whose every chunk was unreadable mined nothing because the model
 * could not be read, not because nothing was minable. That must fail the job
 * rather than report a null result.
 */
export function assertSomeChunkRead(chunksAsked: number, chunksUnread: number): void {
  if (chunksAsked > 0 && chunksUnread === chunksAsked) {
    throw new Error(`none of the ${chunksAsked} mining replies could be read as JSON; the lane mined nothing`);
  }
}
