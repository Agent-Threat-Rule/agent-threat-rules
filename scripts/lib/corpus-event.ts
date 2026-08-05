/**
 * Re-export shim. The canonical shape set lives in src/corpus-event.ts.
 *
 * It was moved there because tsconfig's rootDir is ./src, so src/ cannot import
 * from scripts/ — and src/eval/eval-harness.ts needs the same shapes the
 * false-positive gates charge rules on. Leaving this file as a re-export keeps
 * every existing `./lib/corpus-event.js` import working, and keeps the ratchet
 * in tests/corpus-event-shapes.test.ts (which greps for that specifier) honest.
 *
 * Add nothing here. New exports go in src/corpus-event.ts.
 */
export * from "../../src/corpus-event.js";
