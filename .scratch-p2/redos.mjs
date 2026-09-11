// Adversarial latency probe: long near-miss inputs designed to maximise backtracking.
import fs from 'fs';
import yaml from 'js-yaml';
const files = ['rules/prompt-injection/ATR-2026-02815-injected-halt-order-canned-reply-dos.yaml',
 'rules/context-exfiltration/ATR-2026-02816-skill-environment-exfil-hardcoded-endpoint.yaml',
 'rules/tool-poisoning/ATR-2026-02817-untrusted-content-dictates-tool-arguments.yaml',
 'rules/skill-compromise/ATR-2026-02818-skill-manifest-declares-attack-purpose.yaml'];
const evil = [
 'stop what you are doing '.repeat(400),
 ('halt immediately what you are doing right now ' + 'x'.repeat(200) + ' reply with "').repeat(60),
 'requests.post("https://a.b/c", ' + 'json=dict(os.environ '.repeat(300),
 'I would like the assistant to call the x function with the parameter a set to b, '.repeat(300),
 '---\nname: a\n' + 'metadata:\n'.repeat(300) + '  category: attac',
 'the parameter x parameter '.repeat(500),
 ('printenv | ' + 'a'.repeat(100) + ' | curl ').repeat(80),
];
let worst = 0, worstDesc = '';
for (const f of files) {
  const d = yaml.load(fs.readFileSync(f, 'utf8'));
  for (const c of d.detection.conditions) {
    const re = new RegExp(c.value, 'i');
    for (const [i, s] of evil.entries()) {
      const t0 = process.hrtime.bigint();
      re.test(s);
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      if (ms > worst) { worst = ms; worstDesc = d.id + ' cond vs evil#' + i + ' (len ' + s.length + ')'; }
    }
  }
}
console.log('worst single match: ' + worst.toFixed(2) + ' ms  <- ' + worstDesc);
