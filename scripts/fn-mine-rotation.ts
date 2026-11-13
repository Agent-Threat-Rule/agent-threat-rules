#!/usr/bin/env npx tsx
/**
 * Print the comma-separated corpora the scheduled FN-mine run mines now (UTC),
 * or for `--slot N`. `--all` prints the whole week. Used by
 * .github/workflows/fn-mine-scheduled.yml; see scripts/lib/fn-mine-rotation.ts.
 */
import { parseArgs } from 'node:util';
import { RUNS_PER_DAY, rotationFor, slotAt, weeklyRotation } from './lib/fn-mine-rotation.js';

const { values } = parseArgs({ options: { slot: { type: 'string' }, all: { type: 'boolean', default: false } } });

if (values.all) {
  const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  weeklyRotation().forEach((names, s) => {
    const label = `${days[Math.floor(s / RUNS_PER_DAY)]} ${s % RUNS_PER_DAY === 0 ? '09:00' : '21:00'}`;
    process.stdout.write(`${label}: ${names.join(', ')}\n`);
  });
} else {
  const slot = values.slot !== undefined ? Number(values.slot) : slotAt(new Date());
  process.stdout.write(`${rotationFor(slot).join(',')}\n`);
}
