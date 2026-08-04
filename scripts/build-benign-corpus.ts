#!/usr/bin/env npx tsx
/**
 * build-benign-corpus.ts
 *
 * Builds an expanded benign corpus by pulling text from authoritative
 * public sources that no ATR rule should ever fire on:
 *
 *   1. arxiv abstracts (cs.AI / cs.CR / cs.LG categories) — the
 *      academic discussion of AI security topics. These naturally
 *      contain phrases that an over-eager rule might mistake for an
 *      attack ("prompt injection attacks against...", "jailbreaks
 *      were achieved via...").
 *   2. npm package descriptions for popular AI / dev / framework
 *      packages — written by package authors and not in any attack
 *      context.
 *   3. PyPI package descriptions for popular AI / ML packages.
 *
 * Output:
 *   data/benign-corpus-extended/arxiv.jsonl
 *   data/benign-corpus-extended/npm.jsonl
 *   data/benign-corpus-extended/pypi.jsonl
 *
 * Each line: { text, source, source_id, fetched_at }
 *
 * The quality gate consumes these alongside data/skill-benchmark/benign/
 * to broaden the FP test surface from 432 → ~2,000+ samples.
 *
 * Idempotency: re-running merges new entries; existing entries by
 * source_id are kept. Hard cap of MAX_PER_SOURCE per run.
 *
 * Usage:
 *   npx tsx scripts/build-benign-corpus.ts                  # dry-run
 *   npx tsx scripts/build-benign-corpus.ts --write          # write to disk
 *   npx tsx scripts/build-benign-corpus.ts --source arxiv   # one source
 *   npx tsx scripts/build-benign-corpus.ts --limit 50       # cap per source
 *
 * Exit codes:
 *   0 success
 *   1 fatal (network / parse)
 *   2 partial — one or more sources rate-limited
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve, join } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..");
const OUT_DIR = resolve(REPO_ROOT, "data/benign-corpus-extended");

const args = process.argv.slice(2);
const flag = (n: string) => args.includes(n);
const opt = (n: string): string | undefined => {
  const i = args.indexOf(n);
  return i >= 0 ? args[i + 1] : undefined;
};

const WRITE = flag("--write");
const SOURCE_FILTER = opt("--source");
const MAX_PER_SOURCE = opt("--limit") ? parseInt(opt("--limit")!, 10) : 600;
const VERBOSE = flag("--verbose");

interface BenignSample {
  text: string;
  source: string;
  source_id: string;
  fetched_at: string;
}

function loadExisting(path: string): Map<string, BenignSample> {
  const m = new Map<string, BenignSample>();
  if (!existsSync(path)) return m;
  for (const line of readFileSync(path, "utf-8").split("\n")) {
    const t = line.trim();
    if (!t) continue;
    try {
      const s = JSON.parse(t) as BenignSample;
      m.set(s.source_id, s);
    } catch {
      continue;
    }
  }
  return m;
}

function writeJsonl(path: string, samples: BenignSample[]): void {
  const body = samples.map((s) => JSON.stringify(s)).join("\n") + "\n";
  writeFileSync(path, body, "utf-8");
}

// Jailbreak-exclusion filter. A benign corpus that gates false positives is
// worthless if it contains real jailbreaks — a poisoned "benign" sample would
// suppress the very rule that catches it. arxiv/npm/pypi prose is low-risk, but
// this is a hard safety net so a harvested sample that IS a jailbreak (or quotes
// one verbatim) never lands in the benign gate. Conservative by design: it fires
// only on a persona-swap PAIRED with explicit restriction-removal, or on an
// unambiguous standalone jailbreak phrase — so academic text merely *discussing*
// prompt injection is not dropped.
const JB_PERSONA =
  /\b(you\s+are\s+now|you'?re\s+now|your\s+name\s+is\s+now|you\s+are\s+no\s+longer|you\s+now\s+go\s+by|pretend\s+to\s+be|play\s+the\s+role\s+of)\b/i;
const JB_LEXICON =
  /(unfiltered|uncensored|no\s+restrictions?\b|without\s+(?:any\s+)?(?:restrictions?|filters?|ethical|moral)|(?:no|without|any)\s+content\s+polic|criminal\s+language\s+model|no\s+moral\s+boundaries)/i;
const JB_STRONG =
  /\bdo\s+anything\s+now\b|\bjailbroken\b|welcome\s+to\s+the\s+jailbreak|\bDAN\s+(?:mode|prompt)\b|unfiltered,?\s+(?:completely\s+)?unlimited/i;

function looksLikeJailbreak(text: string): boolean {
  if (JB_STRONG.test(text)) return true;
  return JB_PERSONA.test(text) && JB_LEXICON.test(text);
}

async function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// --- arxiv ---

const ARXIV_CATEGORIES = ["cs.AI", "cs.CR", "cs.LG", "cs.CL"];
// arxiv allows up to 1000 results per query; we keep a comfortable
// margin and split across 4 categories. 350 × 4 categories ≈ 1400
// abstracts, with the per-call sleep keeping us within the
// 3-second-per-query etiquette.
const ARXIV_BATCH = 350;

async function fetchArxiv(): Promise<BenignSample[]> {
  const out: BenignSample[] = [];
  const fetchedAt = new Date().toISOString();
  for (const cat of ARXIV_CATEGORIES) {
    if (out.length >= MAX_PER_SOURCE) break;
    const remaining = MAX_PER_SOURCE - out.length;
    const want = Math.min(ARXIV_BATCH, remaining);
    const u =
      `https://export.arxiv.org/api/query?` +
      `search_query=cat:${cat}` +
      `&sortBy=submittedDate&sortOrder=descending` +
      `&max_results=${want}`;
    if (VERBOSE) console.error(`arxiv ${cat}: GET ${u}`);
    let resp: Response;
    try {
      resp = await fetch(u, {
        headers: { "User-Agent": "atr-benign-corpus-builder" },
      });
    } catch (e) {
      console.error(`arxiv ${cat}: fetch failed: ${e}`);
      continue;
    }
    if (!resp.ok) {
      console.error(`arxiv ${cat}: ${resp.status} ${resp.statusText}`);
      if (resp.status === 429) return out;
      continue;
    }
    const xml = await resp.text();
    // Lightweight extraction of <id> and <summary> tags. arxiv Atom
    // feed is stable enough that regex is fine here.
    const entries = xml.split("<entry>").slice(1);
    for (const e of entries) {
      const idMatch = e.match(/<id>([^<]+)<\/id>/);
      const sumMatch = e.match(/<summary>([\s\S]*?)<\/summary>/);
      if (!idMatch || !sumMatch) continue;
      const id = idMatch[1].trim();
      const text = sumMatch[1].replace(/\s+/g, " ").trim();
      if (text.length < 80) continue;
      out.push({
        text: text.slice(0, 600),
        source: "arxiv",
        source_id: id,
        fetched_at: fetchedAt,
      });
      if (out.length >= MAX_PER_SOURCE) break;
    }
    await sleep(3500); // arxiv requests at most 1 query every 3s
  }
  return out;
}

// --- npm ---

const NPM_PACKAGES = [
  // AI SDKs
  "openai",
  "@anthropic-ai/sdk",
  "@google/genai",
  "@aws-sdk/client-bedrock-runtime",
  "ai",
  "@vercel/ai",
  "@ai-sdk/openai",
  "@ai-sdk/anthropic",
  // LangChain ecosystem
  "langchain",
  "@langchain/core",
  "@langchain/community",
  "@langchain/openai",
  "@langchain/anthropic",
  "@langchain/google-genai",
  "langgraph",
  // MCP ecosystem
  "@modelcontextprotocol/sdk",
  "@modelcontextprotocol/server-filesystem",
  "@modelcontextprotocol/server-github",
  "@modelcontextprotocol/server-postgres",
  "@modelcontextprotocol/server-puppeteer",
  "@modelcontextprotocol/server-brave-search",
  "@modelcontextprotocol/inspector",
  "@modelcontextprotocol/server-everything",
  // LLM tooling
  "llamaindex",
  "ollama",
  "fastify",
  "express",
  "next",
  // testing / observability
  "vitest",
  "jest",
  "mocha",
  "playwright",
  "@playwright/test",
  "cypress",
  "puppeteer",
  // typescript / build
  "typescript",
  "tsx",
  "esbuild",
  "vite",
  "webpack",
  "rollup",
  // utilities
  "lodash",
  "axios",
  "node-fetch",
  "yaml",
  "js-yaml",
  "zod",
  "commander",
  "chalk",
  "dotenv",
  "winston",
  "pino",
  // ai infra
  "@upstash/redis",
  "@upstash/vector",
  "@pinecone-database/pinecone",
  "@qdrant/js-client-rest",
  "weaviate-ts-client",
  "chromadb",
  // popular general purpose
  "react",
  "react-dom",
  "next-auth",
  "drizzle-orm",
  "prisma",
  "pg",
  "mongodb",
  "ioredis",
  "bullmq",
];

async function fetchNpm(): Promise<BenignSample[]> {
  const out: BenignSample[] = [];
  const fetchedAt = new Date().toISOString();
  for (const pkg of NPM_PACKAGES) {
    if (out.length >= MAX_PER_SOURCE) break;
    const u = `https://registry.npmjs.org/${encodeURIComponent(pkg)}`;
    if (VERBOSE) console.error(`npm ${pkg}`);
    let resp: Response;
    try {
      resp = await fetch(u, {
        headers: {
          Accept: "application/json",
          "User-Agent": "atr-benign-corpus-builder",
        },
      });
    } catch (e) {
      console.error(`npm ${pkg}: fetch failed: ${e}`);
      continue;
    }
    if (!resp.ok) {
      if (VERBOSE) console.error(`npm ${pkg}: ${resp.status}`);
      continue;
    }
    let j: {
      description?: string;
      readme?: string;
      "dist-tags"?: { latest?: string };
    };
    try {
      j = (await resp.json()) as typeof j;
    } catch {
      continue;
    }
    const desc = (j.description ?? "").trim();
    if (desc.length >= 40) {
      out.push({
        text: desc,
        source: "npm",
        source_id: pkg,
        fetched_at: fetchedAt,
      });
    }
    // Pull first ~600 chars of README too — README descriptions are
    // longer and contain more diverse language.
    const readme = (j.readme ?? "")
      .replace(/^---[\s\S]*?---/m, "")
      .replace(/^#+\s*.*$/gm, "")
      .replace(/```[\s\S]*?```/g, "")
      .replace(/\s+/g, " ")
      .trim();
    if (readme.length >= 80) {
      out.push({
        text: readme.slice(0, 600),
        source: "npm-readme",
        source_id: `${pkg}::readme`,
        fetched_at: fetchedAt,
      });
    }
    await sleep(100);
  }
  return out;
}

// --- pypi ---

const PYPI_PACKAGES = [
  // AI / LLM
  "openai",
  "anthropic",
  "google-genai",
  "transformers",
  "vllm",
  "litellm",
  // LangChain ecosystem
  "langchain",
  "langchain-core",
  "langchain-community",
  "langchain-openai",
  "langchain-anthropic",
  "langgraph",
  "langsmith",
  // ML
  "torch",
  "tensorflow",
  "numpy",
  "scipy",
  "pandas",
  "scikit-learn",
  "huggingface-hub",
  "diffusers",
  "accelerate",
  "datasets",
  "onnx",
  "onnxruntime",
  "mlflow",
  "ray",
  "wandb",
  // Agent / orchestration
  "crewai",
  "autogen-agentchat",
  "pyautogen",
  "haystack-ai",
  "llama-index",
  "llama-index-core",
  "dspy",
  "dspy-ai",
  "instructor",
  "semantic-kernel",
  "pydantic-ai",
  "fastapi",
  "uvicorn",
  // Red team / safety
  "garak",
  "pyrit",
  "promptfoo",
  "llm-guard",
  "nemoguardrails",
  "guardrails-ai",
  // MCP / tooling
  "mcp",
  "fastmcp",
  // Vector DBs
  "qdrant-client",
  "weaviate-client",
  "chromadb",
  "pinecone-client",
  // General
  "requests",
  "httpx",
  "click",
  "rich",
  "typer",
  "pyyaml",
  "jsonschema",
  "sqlalchemy",
  "psycopg",
  "redis",
];

async function fetchPypi(): Promise<BenignSample[]> {
  const out: BenignSample[] = [];
  const fetchedAt = new Date().toISOString();
  for (const pkg of PYPI_PACKAGES) {
    if (out.length >= MAX_PER_SOURCE) break;
    const u = `https://pypi.org/pypi/${encodeURIComponent(pkg)}/json`;
    if (VERBOSE) console.error(`pypi ${pkg}`);
    let resp: Response;
    try {
      resp = await fetch(u, {
        headers: {
          Accept: "application/json",
          "User-Agent": "atr-benign-corpus-builder",
        },
      });
    } catch (e) {
      console.error(`pypi ${pkg}: fetch failed: ${e}`);
      continue;
    }
    if (!resp.ok) {
      if (VERBOSE) console.error(`pypi ${pkg}: ${resp.status}`);
      continue;
    }
    let j: { info?: { summary?: string; description?: string } };
    try {
      j = (await resp.json()) as typeof j;
    } catch {
      continue;
    }
    const summary = (j.info?.summary ?? "").trim();
    if (summary.length >= 40) {
      out.push({
        text: summary,
        source: "pypi",
        source_id: pkg,
        fetched_at: fetchedAt,
      });
    }
    const desc = (j.info?.description ?? "")
      .replace(/^---[\s\S]*?---/m, "")
      .replace(/^#+\s*.*$/gm, "")
      .replace(/```[\s\S]*?```/g, "")
      .replace(/\s+/g, " ")
      .trim();
    if (desc.length >= 80) {
      out.push({
        text: desc.slice(0, 600),
        source: "pypi-readme",
        source_id: `${pkg}::readme`,
        fetched_at: fetchedAt,
      });
    }
    await sleep(100);
  }
  return out;
}

// --- main ---

async function main(): Promise<void> {
  if (!existsSync(OUT_DIR)) mkdirSync(OUT_DIR, { recursive: true });

  const sources: Record<string, () => Promise<BenignSample[]>> = {
    arxiv: fetchArxiv,
    npm: fetchNpm,
    pypi: fetchPypi,
  };

  const wanted = SOURCE_FILTER ? [SOURCE_FILTER] : Object.keys(sources);

  const summary: Record<string, number> = {};
  for (const src of wanted) {
    const fn = sources[src];
    if (!fn) {
      console.error(
        `unknown source "${src}" — known: ${Object.keys(sources).join(", ")}`,
      );
      continue;
    }
    console.error(`\n=== fetching ${src} ===`);
    let fetched: BenignSample[];
    try {
      fetched = await fn();
    } catch (e) {
      console.error(`${src}: fatal: ${e}`);
      continue;
    }
    console.error(`${src}: fetched ${fetched.length} samples`);

    // Safety net: never let a harvested sample that is itself a jailbreak into
    // the benign gate (see looksLikeJailbreak).
    const clean = fetched.filter((s) => !looksLikeJailbreak(s.text));
    const dropped = fetched.length - clean.length;
    if (dropped > 0) {
      console.error(
        `${src}: dropped ${dropped} sample(s) matching a jailbreak signature (excluded from benign corpus)`,
      );
    }

    const path = join(OUT_DIR, `${src}.jsonl`);
    const existing = loadExisting(path);
    let added = 0;
    for (const s of clean) {
      if (!existing.has(s.source_id)) {
        existing.set(s.source_id, s);
        added += 1;
      }
    }
    summary[src] = added;
    if (WRITE) {
      const arr = [...existing.values()];
      writeJsonl(path, arr);
      console.error(
        `${src}: wrote ${arr.length} total (${added} new) → ${path}`,
      );
    } else {
      console.error(
        `${src}: dry-run, would write ${existing.size} (${added} new)`,
      );
    }
  }

  console.log(
    `::benign-corpus-summary::${JSON.stringify({
      added_per_source: summary,
      total_added: Object.values(summary).reduce((a, b) => a + b, 0),
    })}`,
  );
}

main().catch((e) => {
  console.error("fatal:", e);
  process.exit(1);
});
