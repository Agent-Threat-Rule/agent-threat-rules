/**
 * holdout.ts — read holdout v1 and refuse to read it wrong.
 *
 * data/holdout/v1/ is the corpus the enforce lane is judged on. It is only
 * worth anything while two things stay true: the files are the ones the
 * manifest describes, and no rule was written from them. The first is checked
 * here, on every read — a sample edited by hand after the build would turn a
 * published number into one nobody can reproduce, so a hash mismatch is an
 * error, never a warning. The second is checked by
 * tests/holdout-isolation.test.ts.
 *
 * Built by scripts/holdout/build_holdout_v1.py; described in
 * data/holdout/v1/DATACARD.md.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

export const HOLDOUT_VERSION = "holdout-v1";
export const HOLDOUT_REL_DIR = "data/holdout/v1";

export type HoldoutLabel = "attack" | "benign";

export interface HoldoutSample {
  readonly id: string;
  readonly label: HoldoutLabel;
  readonly slice: string;
  readonly surface: string;
  readonly text: string;
  readonly source: { readonly dataset: string; readonly revision: string; readonly row: string };
  readonly license: string;
}

export interface HoldoutManifest {
  readonly version: string;
  readonly files: Readonly<Record<string, { readonly sha256: string; readonly samples: number }>>;
  readonly slices: Readonly<Record<string, { readonly label: HoldoutLabel; readonly surface: string; readonly kept: number }>>;
  readonly [key: string]: unknown;
}

export interface Holdout {
  readonly manifest: HoldoutManifest;
  readonly attack: readonly HoldoutSample[];
  readonly benign: readonly HoldoutSample[];
  /** sha256 of attack.jsonl and benign.jsonl, as verified. */
  readonly sha256: Readonly<Record<string, string>>;
}

export class HoldoutIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HoldoutIntegrityError";
  }
}

function sha256(body: string): string {
  return createHash("sha256").update(body, "utf8").digest("hex");
}

function parseLines(body: string, file: string, label: HoldoutLabel): readonly HoldoutSample[] {
  const out: HoldoutSample[] = [];
  const lines = body.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (line === "") continue;
    let rec: HoldoutSample;
    try {
      rec = JSON.parse(line) as HoldoutSample;
    } catch (e) {
      throw new HoldoutIntegrityError(`${file}:${i + 1}: not JSON (${String(e).slice(0, 80)})`);
    }
    if (rec.label !== label || typeof rec.text !== "string" || typeof rec.id !== "string") {
      throw new HoldoutIntegrityError(`${file}:${i + 1}: expected a ${label} sample with id and text`);
    }
    out.push(Object.freeze(rec));
  }
  return Object.freeze(out);
}

/** Load holdout v1 from a repository root, verifying every file against the manifest. */
export function loadHoldout(repoRoot: string): Holdout {
  const dir = join(repoRoot, HOLDOUT_REL_DIR);
  const manifestPath = join(dir, "manifest.json");
  if (!existsSync(manifestPath)) throw new HoldoutIntegrityError(`missing ${HOLDOUT_REL_DIR}/manifest.json`);
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as HoldoutManifest;
  if (manifest.version !== HOLDOUT_VERSION) {
    throw new HoldoutIntegrityError(`manifest version ${manifest.version}, expected ${HOLDOUT_VERSION}`);
  }
  const read = (label: HoldoutLabel): { samples: readonly HoldoutSample[]; digest: string } => {
    const file = `${label}.jsonl`;
    const expected = manifest.files[file];
    if (!expected) throw new HoldoutIntegrityError(`manifest lists no ${file}`);
    const body = readFileSync(join(dir, file), "utf8");
    const digest = sha256(body);
    if (digest !== expected.sha256) {
      throw new HoldoutIntegrityError(`${file} sha256 ${digest} does not match the manifest (${expected.sha256})`);
    }
    const samples = parseLines(body, file, label);
    if (samples.length !== expected.samples) {
      throw new HoldoutIntegrityError(`${file} has ${samples.length} samples, manifest says ${expected.samples}`);
    }
    return { samples, digest };
  };
  const attack = read("attack");
  const benign = read("benign");
  return Object.freeze({
    manifest,
    attack: attack.samples,
    benign: benign.samples,
    sha256: Object.freeze({ "attack.jsonl": attack.digest, "benign.jsonl": benign.digest }),
  });
}

/** Count samples per slice. */
export function sliceCounts(samples: readonly HoldoutSample[]): Readonly<Record<string, number>> {
  const out: Record<string, number> = {};
  for (const s of samples) out[s.slice] = (out[s.slice] ?? 0) + 1;
  return Object.freeze(out);
}
