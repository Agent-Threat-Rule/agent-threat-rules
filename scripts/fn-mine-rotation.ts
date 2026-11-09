#!/usr/bin/env npx tsx
/**
 * Print the comma-separated corpora the daily FN-mine cron mines today (UTC),
 * or for `--weekday N`. `--all` prints the whole week. Used by
 * .github/workflows/fn-mine-scheduled.yml; see scripts/lib/fn-mine-rotation.ts.
 */
import { parseArgs } from 'node:util';
import { rotationFor, weeklyRotation } from './lib/fn-mine-rotation.js';

const { values } = parseArgs({ options: { weekday: { type: 'string' }, all: { type: 'boolean', default: false } } });

if (values.all) {
  const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  weeklyRotation().forEach((names, d) => process.stdout.write(`${days[d]}: ${names.join(', ')}\n`));
} else {
  const weekday = values.weekday !== undefined ? Number(values.weekday) : new Date().getUTCDay();
  process.stdout.write(`${rotationFor(weekday).join(',')}\n`);
}
