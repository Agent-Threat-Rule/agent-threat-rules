/**
 * What the evaluation harness's embedding tier (Tier 2.5) ran with, so a
 * measurement that used it names the exact model files and attack-vector set.
 *
 * transformers.js loads `Xenova/all-MiniLM-L6-v2` at revision `main` and caches
 * the files it downloads; this module hashes the cached files, so the record
 * says what was actually loaded rather than what was requested. When the
 * quantized ONNX file's SHA-256 is one this module knows, it also names the
 * Hub commit that file came from.
 *
 * @module agent-threat-rules/eval/embedding-provenance
 */

import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { EMBEDDING_MODEL_ID } from '../embedding/model-loader.js';
import { EVAL_EMBEDDING_SIMILARITY_THRESHOLD } from './eval-harness.js';

/** The files transformers.js reads for a quantized feature-extraction pipeline. */
export const EMBEDDING_MODEL_FILES: readonly string[] = [
  'config.json',
  'tokenizer.json',
  'tokenizer_config.json',
  'onnx/model_quantized.onnx',
];

/**
 * SHA-256 of onnx/model_quantized.onnx -> the Xenova/all-MiniLM-L6-v2 commit it
 * belongs to. Checked 2026-10-19 against the Hub: the LFS sha256 of that file at
 * 751bff37 (2025-07-22, the head of `main` that day), whose config.json,
 * tokenizer.json and tokenizer_config.json git blob ids also equal the cached
 * files'.
 */
export const KNOWN_MODEL_REVISIONS: Readonly<Record<string, string>> = {
  afdb6f1a0e45b715d0bb9b11772f032c399babd23bfc31fed1c170afc848bdb1: '751bff37182d3f1213fa05d7196b954e230abad9',
};

export interface EmbeddingProvenance {
  readonly model_id: string;
  readonly quantized: true;
  readonly revision_requested: 'main';
  /** Hub commit whose quantized ONNX file has the loaded file's sha256, or null when not known here. */
  readonly revision_resolved: string | null;
  readonly transformers_package: '@xenova/transformers';
  readonly transformers_version: string;
  /** sha256 of each model file as loaded from the transformers.js cache; null if the file is absent. */
  readonly model_files_sha256: Readonly<Record<string, string | null>>;
  readonly attack_embeddings: string;
  readonly attack_embeddings_sha256: string;
  readonly similarity_threshold: number;
}

function sha256(path: string): string | null {
  return existsSync(path) ? createHash('sha256').update(readFileSync(path)).digest('hex') : null;
}

function transformersDir(): string {
  return dirname(createRequire(import.meta.url).resolve('@xenova/transformers/package.json'));
}

/** Where transformers.js caches model files: `env.cacheDir`, by default `<package>/.cache/`. */
async function transformersCacheDir(): Promise<string> {
  const { env } = (await import('@xenova/transformers')) as { env: { cacheDir?: string | null } };
  return env.cacheDir ?? join(transformersDir(), '.cache');
}

export function describeEmbeddingFiles(
  cacheDir: string,
  transformersVersion: string,
  attackEmbeddingsPath: string,
  attackEmbeddingsRel: string
): EmbeddingProvenance {
  const files = Object.fromEntries(
    EMBEDDING_MODEL_FILES.map((f) => [f, sha256(join(cacheDir, EMBEDDING_MODEL_ID, f))] as const)
  );
  const onnx = files['onnx/model_quantized.onnx'];
  const embeddings = sha256(attackEmbeddingsPath);
  if (embeddings === null) throw new Error(`attack embeddings not found: ${attackEmbeddingsPath}`);
  return {
    model_id: EMBEDDING_MODEL_ID,
    quantized: true,
    revision_requested: 'main',
    revision_resolved: onnx ? KNOWN_MODEL_REVISIONS[onnx] ?? null : null,
    transformers_package: '@xenova/transformers',
    transformers_version: transformersVersion,
    model_files_sha256: files,
    attack_embeddings: attackEmbeddingsRel,
    attack_embeddings_sha256: embeddings,
    similarity_threshold: EVAL_EMBEDDING_SIMILARITY_THRESHOLD,
  };
}

/** The record for the installed @xenova/transformers and its cache. */
export async function embeddingProvenance(attackEmbeddingsPath: string, attackEmbeddingsRel: string): Promise<EmbeddingProvenance> {
  const pkg = JSON.parse(readFileSync(join(transformersDir(), 'package.json'), 'utf-8')) as { version: string };
  return describeEmbeddingFiles(await transformersCacheDir(), pkg.version, attackEmbeddingsPath, attackEmbeddingsRel);
}
