// Quick schema validation across all rules to verify language field doesn't break.
import { readFileSync, readdirSync, statSync } from 'fs';
import { join } from 'path';
import * as yaml from 'js-yaml';
import Ajv from 'ajv/dist/2020.js';

function walk(dir) {
  const out = [];
  for (const f of readdirSync(dir)) {
    const p = join(dir, f);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if (f.endsWith('.yaml')) out.push(p);
  }
  return out;
}

const schema = yaml.load(readFileSync('./spec/atr-schema.yaml', 'utf8'));
const ajv = new Ajv({ strict: false, allErrors: true });
const validate = ajv.compile(schema);

const files = walk('./rules');
let pass = 0, fail = 0;
const samples = [];

for (const f of files) {
  try {
    const rule = yaml.load(readFileSync(f, 'utf8'));
    if (validate(rule)) pass++;
    else {
      fail++;
      if (samples.length < 5) samples.push(`${f}: ${JSON.stringify(validate.errors?.[0]).slice(0, 200)}`);
    }
  } catch {
    fail++;
  }
}

console.log(`Total: ${files.length}\nPass:  ${pass}\nFail:  ${fail}`);
for (const s of samples) console.log(' -', s);
