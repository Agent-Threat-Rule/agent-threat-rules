import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import yaml from 'js-yaml';
import type { CiscoSignature, SignatureFile } from './transform.js';

export interface PackDiff {
  readonly added: readonly CiscoSignature[];
  readonly removed: readonly string[];
  readonly changed: readonly {
    readonly atr_id: string;
    /** Fields present on both sides whose value differs. */
    readonly fields: readonly string[];
    /** Fields the previous pack did not carry at all. */
    readonly fieldsAdded: readonly string[];
  }[];
  readonly unchanged: number;
}

const COMPARED_FIELDS = [
  'id',
  'atr_url',
  'category',
  'severity',
  'maturity',
  'patterns',
  'description',
  'remediation',
] as const;

/** Read the signatures out of an existing vendored pack directory. */
export function readExistingPack(packDir: string): Map<string, CiscoSignature> {
  const signaturesDir = join(packDir, 'signatures');
  const out = new Map<string, CiscoSignature>();
  for (const name of readdirSync(signaturesDir).sort()) {
    if (!name.endsWith('.yaml')) continue;
    const doc = yaml.load(readFileSync(join(signaturesDir, name), 'utf8')) as {
      signatures?: CiscoSignature[];
    };
    for (const signature of doc?.signatures ?? []) out.set(signature.atr_id, signature);
  }
  return out;
}

function hasField(signature: CiscoSignature, field: string): boolean {
  return (signature as unknown as Record<string, unknown>)[field] !== undefined;
}

function fieldValue(signature: CiscoSignature, field: string): string {
  const raw = (signature as unknown as Record<string, unknown>)[field];
  return Array.isArray(raw) ? JSON.stringify(raw) : String(raw ?? '');
}

export function diffPacks(
  previous: ReadonlyMap<string, CiscoSignature>,
  files: readonly SignatureFile[],
): PackDiff {
  const next = new Map<string, CiscoSignature>();
  for (const file of files) for (const s of file.signatures) next.set(s.atr_id, s);

  const added = [...next.values()].filter((s) => !previous.has(s.atr_id));
  const removed = [...previous.keys()].filter((id) => !next.has(id)).sort();
  const changed: { atr_id: string; fields: string[]; fieldsAdded: string[] }[] = [];
  let unchanged = 0;
  for (const [atr_id, signature] of next) {
    const before = previous.get(atr_id);
    if (!before) continue;
    const differing = COMPARED_FIELDS.filter(
      (field) => fieldValue(before, field) !== fieldValue(signature, field),
    );
    // A field the previous pack never carried is an addition, not an edit;
    // counting the two together would report 710 "changed" rules for what is
    // one new key.
    const fieldsAdded = differing.filter((f) => !hasField(before, f) && hasField(signature, f));
    const fields = differing.filter((f) => !fieldsAdded.includes(f));
    if (fields.length > 0 || fieldsAdded.length > 0) {
      changed.push({ atr_id, fields: [...fields], fieldsAdded: [...fieldsAdded] });
    } else unchanged += 1;
  }
  changed.sort((a, b) => a.atr_id.localeCompare(b.atr_id));
  return { added, removed, changed, unchanged };
}

export function summariseByCategory(signatures: readonly CiscoSignature[]): [string, number][] {
  const counts = new Map<string, number>();
  for (const s of signatures) counts.set(s.category, (counts.get(s.category) ?? 0) + 1);
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

export function summariseByMaturity(signatures: readonly CiscoSignature[]): [string, number][] {
  const order = ['stable', 'test', 'experimental', 'draft'];
  const counts = new Map<string, number>();
  for (const s of signatures) counts.set(s.maturity ?? 'unset', (counts.get(s.maturity ?? 'unset') ?? 0) + 1);
  return [...counts.entries()].sort((a, b) => order.indexOf(a[0]) - order.indexOf(b[0]));
}

export function summariseBySeverity(signatures: readonly CiscoSignature[]): [string, number][] {
  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const counts = new Map<string, number>();
  for (const s of signatures) counts.set(s.severity, (counts.get(s.severity) ?? 0) + 1);
  return [...counts.entries()].sort((a, b) => order.indexOf(a[0]) - order.indexOf(b[0]));
}
