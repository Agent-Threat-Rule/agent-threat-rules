#!/usr/bin/env node
// Reads the latest agent-threat-rules version from the npm registry once,
// before `next build` / `next dev`, and writes it to .generated/npm-latest.json
// for lib/versions.ts. Fetching inside the build workers does not work: they
// parse every rule YAML synchronously, the event loop stays blocked past any
// sane timeout, and the timer fires before the response is read.
//
// Never fails the build. When the registry cannot be read it writes
// {"version": null} and the site labels the version "package.json" instead of
// "npm".

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const URL = "https://registry.npmjs.org/agent-threat-rules/latest";
const OUT = join(process.cwd(), ".generated", "npm-latest.json");
const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

async function latest() {
  try {
    const res = await fetch(URL, { signal: AbortSignal.timeout(10000) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const { version } = await res.json();
    if (typeof version !== "string" || !SEMVER.test(version)) throw new Error(`unexpected version ${String(version)}`);
    return version;
  } catch (err) {
    console.warn(`fetch-npm-version: npm registry not read (${err.message}); the site will label package.json instead`);
    return null;
  }
}

const version = await latest();
mkdirSync(join(process.cwd(), ".generated"), { recursive: true });
writeFileSync(OUT, JSON.stringify({ version, fetched_at: new Date().toISOString() }, null, 2) + "\n");
console.log(`fetch-npm-version: ${version ?? "not available"} -> .generated/npm-latest.json`);
