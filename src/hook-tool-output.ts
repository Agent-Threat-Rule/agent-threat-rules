/**
 * The text of a tool's output, as a PostToolUse hook input carries it.
 *
 * Claude Code sends the output at the top level of the hook input, as
 * tool_response, and its value is the tool's own output object: Bash gives
 * { stdout, stderr, interrupted, isImage, ... }, Read gives { type, file: {
 * filePath, content, ... } }, an MCP tool gives its content blocks, and some
 * tools give a string. The shape depends on the tool and changes between Claude
 * Code versions, so no list of fields to read is kept here: every string in the
 * output is text the model may read, and every one is kept, as written.
 * JSON-encoding the object instead would turn a newline into the two characters
 * `\` `n` and change what a pattern matches.
 *
 * Some strings are left out, by the keys the shipped Claude Code (2.1.280) uses
 * for them:
 *
 *   - Binary data: Read's image under `base64`, a notebook output image under
 *     `image_data`, an MCP image or audio block's `data` (also under a source of
 *     type `base64`), an MCP resource's `blob`, and Bash's stdout when the command
 *     printed nothing but an image (`isImage`). Besides not being text, it is
 *     long: the engine scans a value over 100,000 characters in windows
 *     (MAX_EVAL_LENGTH in src/engine.ts) and only the first and last 500,000
 *     characters of one over 1,000,000 (MAX_SCAN_LENGTH), so one screenshot
 *     beside a page's text would cost window tests for nothing and could push
 *     the text out of what is scanned.
 *   - What Claude Code keeps from the model: an MCP block's `_meta`, Bash's
 *     `bashEditDiff` and `gitOperation`, and the `prompt` and `status` an Agent or
 *     Task result repeats back.
 *   - Labels and echoes: a short tag under `type`, `media_type` or `mimeType`,
 *     WebFetch's `codeText`, Grep's `mode`, and any string the tool only repeats
 *     from its input, such as the path Read was given. They are not what the
 *     tool returned, and ahead of it they would keep a pattern anchored at the
 *     start of the text from reading the output itself. A long or free-text
 *     value under a label key is kept, so a key a server picks cannot hide one.
 *
 * The tools that edit a file (Edit, MultiEdit, Write, NotebookEdit) return the
 * edit they made beside the file's previous contents and diff, which the model
 * does not get back. Nothing of theirs is read: their event is built from their
 * input, as before. An object nested deeper than the walk goes is kept as its
 * JSON, less the keys above.
 *
 * @module agent-threat-rules/hook-tool-output
 */

/** Keys left out of any tool's output: binary data and metadata the model does not see. */
const SKIPPED_KEYS: ReadonlySet<string> = new Set(['base64', 'image_data', 'blob', '_meta']);

/** Keys left out when their value is a short tag, not free text. */
const LABEL_KEYS: ReadonlySet<string> = new Set(['type', 'media_type', 'mimeType']);
const LABEL = /^[\w./+-]{1,64}$/;

/** Keys left out of one tool's output. */
const AGENT_ECHO: ReadonlySet<string> = new Set(['prompt', 'status']);
const SKIPPED_BY_TOOL: Readonly<Record<string, ReadonlySet<string>>> = {
  Bash: new Set(['bashEditDiff', 'gitOperation']),
  WebFetch: new Set(['codeText']),
  Grep: new Set(['mode']),
  Agent: AGENT_ECHO,
  Task: AGENT_ECHO,
};
const NO_KEYS: ReadonlySet<string> = new Set();

/** The tools whose output is the edit they made; their event is built from their input. */
const FILE_EDIT_TOOLS: ReadonlySet<string> = new Set(['Edit', 'MultiEdit', 'Write', 'NotebookEdit']);

/** The `type` of an object whose `data` is binary (an MCP image or audio block, a base64 source). */
const BINARY_TYPES: ReadonlySet<string> = new Set(['base64', 'image', 'audio']);

/** Bash's stdout when the command printed only an image, as Claude Code detects one. */
const IMAGE_DATA_URL = /^data:image\/[a-z0-9.+_-]+;base64,[A-Za-z0-9+/=\r\n]*$/i;

/** How deep the walk goes. The deepest Claude Code output nests seven levels. */
const MAX_DEPTH = 8;

/**
 * Every string in a tool's output, in order, joined by newlines; '' when the
 * output holds no text of its own, and for a tool that edits a file.
 */
export function toolOutputText(toolName: string, toolResponse: unknown, toolInput: unknown = undefined): string {
  if (FILE_EDIT_TOOLS.has(toolName)) return '';
  const skipped = Object.hasOwn(SKIPPED_BY_TOOL, toolName) ? SKIPPED_BY_TOOL[toolName] : NO_KEYS;
  const echoes = new Set(textsOf(toolInput, 0, NO_KEYS));
  return textsOf(toolResponse, 0, skipped)
    .filter((text) => !echoes.has(text))
    .join('\n');
}

function textsOf(value: unknown, depth: number, skipped: ReadonlySet<string>): readonly string[] {
  if (typeof value === 'string') return value === '' ? [] : [value];
  if (value === null || typeof value !== 'object') return [];
  if (depth >= MAX_DEPTH) return [deepJson(value, skipped)];
  const children = Array.isArray(value) ? value : textChildren(value as Record<string, unknown>, skipped);
  return children.flatMap((child) => textsOf(child, depth + 1, skipped));
}

function textChildren(object: Record<string, unknown>, skipped: ReadonlySet<string>): readonly unknown[] {
  return Object.entries(object)
    .filter(([key, child]) => !isSkipped(object, key, child, skipped))
    .map(([, child]) => child);
}

/** An object past the walk's depth, as JSON, without what the walk leaves out. */
function deepJson(value: object, skipped: ReadonlySet<string>): string {
  return JSON.stringify(value, function (this: Record<string, unknown>, key: string, child: unknown) {
    return key !== '' && isSkipped(this, key, child, skipped) ? undefined : child;
  });
}

function isSkipped(parent: Record<string, unknown>, key: string, value: unknown, skipped: ReadonlySet<string>): boolean {
  if (SKIPPED_KEYS.has(key) || skipped.has(key)) return true;
  if (LABEL_KEYS.has(key)) return typeof value === 'string' && LABEL.test(value);
  if (key === 'data') return typeof parent['type'] === 'string' && BINARY_TYPES.has(parent['type']);
  if (key === 'stdout') return parent['isImage'] === true && typeof value === 'string' && IMAGE_DATA_URL.test(value);
  return false;
}
