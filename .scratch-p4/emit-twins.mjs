import { readFileSync, writeFileSync } from 'node:fs';
import { load } from 'js-yaml';
const files = process.argv.slice(2);
const out = [];
for (const f of files) {
  const r = load(readFileSync(f, 'utf8'));
  (r.test_cases?.true_negatives ?? []).forEach((t, i) => {
    out.push(JSON.stringify({ text: t.input, source: 'p4-paper-rule-benign-twin', source_id: `${r.id}-tn${String(i + 1).padStart(2, '0')}` }));
  });
}
writeFileSync('data/benign-corpus-extended/p4-paper-rules-benign-twins.jsonl', out.join('\n') + '\n');
console.log(out.length, 'twins from', files.length, 'rules');
