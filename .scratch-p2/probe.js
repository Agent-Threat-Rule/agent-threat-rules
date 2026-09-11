// Probe: evaluate arbitrary strings against the live 785-rule corpus.
// Usage: node .scratch-p2/probe.js <cases.json>
// case: {id, text, type, scanContext?}
const { ATREngine } = require('../dist/engine.js');
const fs = require('fs');

(async () => {
  const eng = new ATREngine({ rulesDir: 'rules', lane: 'hunt' });
  await eng.loadRules();
  const cases = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
  for (const c of cases) {
    const ev = { type: c.type || 'tool_response', content: c.text };
    if (c.scanContext) ev.scanContext = c.scanContext;
    const m = await eng.evaluate(ev);
    const ids = m.map((x) => x.rule.id + '(' + x.rule.severity + ')');
    console.log((ids.length ? 'HIT  ' : 'MISS ') + c.id + '  ' + (ids.join(',') || '-'));
  }
})();
