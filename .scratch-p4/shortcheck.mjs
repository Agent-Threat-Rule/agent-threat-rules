import { readFileSync } from 'node:fs';
import { load } from 'js-yaml';
const SHORT = ['nc','sh','cp','rm','curl','wget','exec','eval','run','cat'];
for (const f of process.argv.slice(2)) {
  const r = load(readFileSync(f, 'utf8'));
  r.detection.conditions.forEach((c, i) => {
    const v = String(c.value);
    for (const t of SHORT) {
      const re = new RegExp(t, 'g');
      let m;
      while ((m = re.exec(v)) !== null) {
        const before = v.slice(Math.max(0, m.index - 8), m.index);
        const after = v.slice(m.index + t.length, m.index + t.length + 8);
        if (/[a-z]$/.test(before) || /^[a-z]/.test(after)) continue; // part of a longer word
        console.log(`${r.id} cond${i} "${t}" ctx=${JSON.stringify(before + '[' + t + ']' + after)}`);
      }
    }
  });
}
