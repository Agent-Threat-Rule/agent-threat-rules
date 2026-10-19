/**
 * Embedding model loader.
 *
 * Lazy-loads all-MiniLM-L6-v2 via @xenova/transformers (optional dep).
 * Model is ~22MB, cached to disk after first download.
 * Runs in pure JS/WASM -- no native bindings needed.
 *
 * @module agent-threat-rules/embedding/model-loader
 */

export interface EmbeddingModel {
  /** Encode text to embedding vector */
  encode(text: string): Promise<Float32Array>;
  /** Encode multiple texts (batched) */
  encodeBatch(texts: readonly string[]): Promise<Float32Array[]>;
  /** Initialize / load the model */
  initialize(): Promise<void>;
  /** Model output dimension */
  readonly dimension: number;
  /** Whether model is loaded */
  readonly isLoaded: boolean;
}

/** HuggingFace model id the embedding tier loads (transformers.js resolves revision `main`). */
export const EMBEDDING_MODEL_ID = 'Xenova/all-MiniLM-L6-v2';
const MODEL_NAME = EMBEDDING_MODEL_ID;
const DIMENSION = 384;

export class TransformersJSModel implements EmbeddingModel {
  readonly dimension = DIMENSION;
  private pipeline: unknown = null;

  get isLoaded(): boolean {
    return this.pipeline !== null;
  }

  /** Lazy-load the model on first use */
  async initialize(): Promise<void> {
    if (this.pipeline) return;

    try {
      // Dynamic import to keep @xenova/transformers optional
      const { pipeline } = await import('@xenova/transformers');
      this.pipeline = (await pipeline('feature-extraction', MODEL_NAME, {
        quantized: true,
      })) as typeof this.pipeline;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes('Cannot find module') || msg.includes('MODULE_NOT_FOUND')) {
        throw new Error(
          'Embedding model requires @xenova/transformers. Install: npm install @xenova/transformers'
        );
      }
      throw new Error(`Failed to load embedding model: ${msg}`);
    }
  }

  async encode(text: string): Promise<Float32Array> {
    if (!this.pipeline) await this.initialize();

    const pipelineFn = this.pipeline as (input: string[], options?: Record<string, unknown>) => Promise<{ data: Float32Array }>;
    const output = await pipelineFn([text], { pooling: 'mean', normalize: true });
    return new Float32Array(output.data.slice(0, DIMENSION));
  }

  async encodeBatch(texts: readonly string[]): Promise<Float32Array[]> {
    if (!this.pipeline) await this.initialize();

    const pipelineFn = this.pipeline as (input: string[], options?: Record<string, unknown>) => Promise<{ data: Float32Array }>;
    const results: Float32Array[] = [];
    // Process one at a time to control memory
    for (const text of texts) {
      const output = await pipelineFn([text], { pooling: 'mean', normalize: true });
      results.push(new Float32Array(output.data.slice(0, DIMENSION)));
    }
    return results;
  }
}

/** Create a no-op model for testing */
export class MockEmbeddingModel implements EmbeddingModel {
  readonly dimension = DIMENSION;
  readonly isLoaded = true;
  private readonly mockVectors: Map<string, Float32Array>;

  constructor(mockVectors?: Map<string, Float32Array>) {
    this.mockVectors = mockVectors ?? new Map();
  }

  async initialize(): Promise<void> {
    // No-op for mock
  }

  async encode(text: string): Promise<Float32Array> {
    const existing = this.mockVectors.get(text);
    if (existing) return existing;
    // Generate deterministic vector from text hash
    const vec = new Float32Array(DIMENSION);
    for (let i = 0; i < DIMENSION; i++) {
      vec[i] = Math.sin(text.charCodeAt(i % text.length) * (i + 1) * 0.01);
    }
    // Normalize
    let mag = 0;
    for (let i = 0; i < DIMENSION; i++) mag += vec[i]! * vec[i]!;
    mag = Math.sqrt(mag);
    for (let i = 0; i < DIMENSION; i++) vec[i]! /= mag;
    return vec;
  }

  async encodeBatch(texts: readonly string[]): Promise<Float32Array[]> {
    return Promise.all(texts.map((t) => this.encode(t)));
  }
}
