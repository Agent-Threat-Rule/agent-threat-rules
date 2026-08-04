/**
 * corpus-event.ts — re-export shim.
 *
 * The canonical shape set now lives at src/corpus-event.ts. It had to move:
 * src/eval/eval-harness.ts (the harness behind `npm run eval` / `npm run
 * eval:pint`, whose numbers are published) needs the same shapes, and tsconfig
 * pins rootDir to ./src, so src/ cannot import from scripts/.
 *
 * This file stays so that every script keeps importing "./lib/corpus-event.js"
 * — the path tests/corpus-event-shapes.test.ts greps for when it enforces that
 * no harness hand-rolls its own event shape.
 *
 * @module scripts/lib/corpus-event
 */
export * from "../../src/corpus-event.js";
