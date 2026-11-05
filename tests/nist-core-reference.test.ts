/**
 * Pin the Core definitions involved in the NIST mapping errata to an independent
 * published source. Valid identifiers alone do not catch definition drift in the
 * generator's reference: shortened statements can omit the conditions that
 * distinguish organizational accountability, planned responses, and deactivation.
 *
 * Source: NIST AI 100-1, AI RMF 1.0 (January 2023), Tables 1, 2, and 4.
 * https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf
 * Printed pages 22, 23, 28, 32 (PDF pages 27, 28, 33, 37), checked 2026-11-05.
 * PDF line wrapping and discretionary hyphens are normalized below.
 * This offline test reads the reference data only; it never imports the API
 * generator or invokes a model. It validates definitions, not rule mappings.
 */
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';

const { valids } = JSON.parse(readFileSync(
  new URL('../data/compliance-frameworks/nist_ai_rmf.json', import.meta.url),
  'utf8',
)) as { valids: Record<string, string> };

// Authoritative statements, rather than the generator's own paraphrases.
const OFFICIAL_CORE: Record<string, string> = {
  'GV.1.2': 'The characteristics of trustworthy AI are integrated into organizational policies, processes, procedures, and practices.',
  'GV.2.1': 'Roles and responsibilities and lines of communication related to mapping, measuring, and managing AI risks are documented and are clear to individuals and teams throughout the organization.',
  'MP.5.2': 'Practices and personnel for supporting regular engagement with relevant AI actors and integrating feedback about positive, negative, and unanticipated impacts are in place and documented.',
  'MG.1.3': 'Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.',
  'MG.2.2': 'Mechanisms are in place and applied to sustain the value of deployed AI systems.',
  'MG.2.3': 'Procedures are followed to respond to and recover from a previously unknown risk when it is identified.',
  'MG.2.4': 'Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use.',
};

describe('NIST AI RMF Core reference definitions', () => {
  for (const [id, statement] of Object.entries(OFFICIAL_CORE)) {
    it(`${id} preserves the official Core conditions`, () => {
      expect(valids[id]).toBe(statement);
    });
  }
});
