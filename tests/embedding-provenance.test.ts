import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  EMBEDDING_MODEL_FILES,
  KNOWN_MODEL_REVISIONS,
  describeEmbeddingFiles,
} from '../src/eval/embedding-provenance.js';
import { EMBEDDING_MODEL_ID } from '../src/embedding/model-loader.js';
import { EVAL_EMBEDDING_SIMILARITY_THRESHOLD } from '../src/eval/eval-harness.js';

const sha = (s: string) => createHash('sha256').update(s).digest('hex');

function cache(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'emb-prov-'));
  for (const [rel, body] of Object.entries(files)) {
    const p = join(dir, EMBEDDING_MODEL_ID, rel);
    mkdirSync(join(p, '..'), { recursive: true });
    writeFileSync(p, body);
  }
  return dir;
}

describe('embedding provenance', () => {
  it('hashes every model file as loaded and the attack-vector set', () => {
    const dir = cache(Object.fromEntries(EMBEDDING_MODEL_FILES.map((f) => [f, `body of ${f}`])));
    const vectors = join(dir, 'attack-embeddings.json');
    writeFileSync(vectors, '[]');
    const p = describeEmbeddingFiles(dir, '2.17.2', vectors, 'data/attack-embeddings.json');
    expect(p.model_id).toBe('Xenova/all-MiniLM-L6-v2');
    expect(p.transformers_version).toBe('2.17.2');
    expect(p.model_files_sha256['onnx/model_quantized.onnx']).toBe(sha('body of onnx/model_quantized.onnx'));
    expect(p.attack_embeddings_sha256).toBe(sha('[]'));
    expect(p.similarity_threshold).toBe(EVAL_EMBEDDING_SIMILARITY_THRESHOLD);
    // An unknown ONNX file names no Hub commit rather than a guessed one.
    expect(p.revision_resolved).toBeNull();
  });

  it('names the Hub commit only for a known ONNX digest, and null for a missing file', () => {
    const [knownSha, commit] = Object.entries(KNOWN_MODEL_REVISIONS)[0]!;
    expect(commit).toMatch(/^[0-9a-f]{40}$/);
    expect(knownSha).toMatch(/^[0-9a-f]{64}$/);
    const dir = cache({ 'config.json': '{}' });
    const vectors = join(dir, 'v.json');
    writeFileSync(vectors, '[]');
    const p = describeEmbeddingFiles(dir, 'x', vectors, 'v.json');
    expect(p.model_files_sha256['onnx/model_quantized.onnx']).toBeNull();
    expect(p.revision_resolved).toBeNull();
  });

  it('fails when the attack-vector set is missing', () => {
    const dir = cache({});
    expect(() => describeEmbeddingFiles(dir, 'x', join(dir, 'nope.json'), 'nope.json')).toThrow(/not found/);
  });
});
