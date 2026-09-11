import { readFileSync } from 'node:fs';
import { load } from 'js-yaml';
const tn = (f) => (load(readFileSync(f, 'utf8')).test_cases.true_negatives).map(t => t.input);

const cases = [
  { name: '02845 draft: wallet layer accepted 0x ETH addresses',
    file: 'rules/skill-compromise/ATR-2026-02845-agent-cryptomining-payload.yaml',
    re: /stratum\+(?:tcp|tcps|ssl):\/\/[\s\S]{0,300}\b(?:4[0-9ab][1-9a-hj-np-zA-HJ-NP-Z]{93}|0x[a-f0-9]{40})\b/i },
  { name: '02846 draft: broadcast-verbatim WITHOUT the recursion clause and WITHOUT the clause anchor',
    file: 'rules/agent-manipulation/ATR-2026-02846-self-replicating-agent-message.yaml',
    re: /(?:forward|relay|resend|send|pass|propagate|broadcast|repeat|copy|share|transmit)\s+(?:this|these|the\s+(?:following|above|entire|same))\s+(?:\w+\s+){0,2}(?:message|instruction|text|prompt|note|content|payload|directive)s?\s+(?:verbatim|unchanged|word[\s-]for[\s-]word|exactly\s+as\s+(?:written|received|is)|in\s+full|as[\s-]is)\s*,?\s*(?:on\s+|along\s+|onward\s+)?to\s+(?:every|each|all|any)\s+(?:(?:of\s+the|other|connected|downstream|neighbou?ring|remaining|nearby)\s+){0,3}(?:agents?|assistants?|models?|bots?|llms?|sub-?agents?|copilots?)\b/i },
  { name: '02846 draft: standalone "reply with nothing except this message" condition',
    file: 'rules/agent-manipulation/ATR-2026-02846-self-replicating-agent-message.yaml',
    re: /(?:reply|respond|answer|output|return)\s+(?:to\s+\w+\s+)?with\s+(?:nothing|no\s+(?:other\s+)?(?:text|content|words))\s+(?:else\s+)?(?:except|but|other\s+than|besides)\s+(?:this|the\s+same)\s+(?:exact\s+)?(?:message|text|instruction|content|prompt|note)/i },
  { name: '02847 draft: split-below-threshold WITHOUT the clause anchor / base-form restriction',
    file: 'rules/prompt-injection/ATR-2026-02847-injected-transaction-structuring.yaml',
    re: /(?:\bsplit\w*|\bdivid\w+|\bstructur\w+|break\w*\s+up)[\s\S]{0,140}\b(?:payments?|transfers?|deposits?|withdrawals?|transactions?|amounts?|funds?)\b[\s\S]{0,140}(?:under|below|beneath)\s+(?:the\s+)?(?:reporting|declaration|disclosure|aml|kyc|ctr)\s*(?:threshold|limit|trigger|requirement)/i },
  { name: '02848 draft: affirmation set included "yes" and "here is"',
    file: 'rules/prompt-injection/ATR-2026-02848-response-prefix-compliance-dictation.yaml',
    re: /(?:^|[.!?;\n\r]\s*|["'(\[]\s*|\b(?:please|now|then|also|and|next|remember|important|first|instead|finally|always|you\s+must|you\s+should)\s*[,:]?\s+)(?:start|begin|open|preface|prefix)\s+(?:your|the|each|every)\s+(?:response|reply|answer|output|message|completion)\s+(?:with|by\s+saying|using)\s+(?:the\s+(?:exact|following|literal|precise)?\s*(?:sentence|phrase|words?|string|text|line)\s+)?["'“‘]?\s*(?:sure|absolutely|certainly|of\s+course|definitely|gladly|yes\b|here\s+(?:is|are)|understood|no\s+problem)/i },
  { name: '02849 draft: Layer 1 needed only ONE account-held identifier',
    file: 'rules/context-exfiltration/ATR-2026-02849-same-site-ugc-exfiltration.yaml',
    re: /(?:^|[.!?;:\n\r]\s*|,\s+|["'(\[]\s*|\b(?:please|now|then|also|and|next|first|finally|kindly|immediately|you\s+must|you\s+should)\s+)(?:post|publish|leave|submit|write|add|place|paste|enter|drop|put)\s+(?:[\w-]+\s+){0,4}(?:comments?|reviews?|repl(?:y|ies)|ratings?|feedback)\b[\s\S]{0,300}(?:(?:\bsaved\b|\bstored\b|\bon\s+file\b|from\s+(?:your|the)\s+(?:account|profile|order\s+history|dashboard|settings)|in\s+(?:your|the)\s+(?:account|profile)|account\s+profile)[\s\S]{0,160}(?:order\s+(?:number|id|reference)|billing\s+address|shipping\s+address|phone\s+number|full\s+name|transaction\s+id)|(?:order\s+(?:number|id|reference)|billing\s+address|shipping\s+address|phone\s+number|full\s+name|transaction\s+id)[\s\S]{0,160}(?:\bsaved\b|\bstored\b|\bon\s+file\b|from\s+(?:your|the)\s+(?:account|profile)|account\s+profile))/i },
  { name: '02849 draft: Layer 2 without the mandatory retrieval verb',
    file: 'rules/context-exfiltration/ATR-2026-02849-same-site-ugc-exfiltration.yaml',
    re: /(?:order\s+(?:number|id|reference)|billing\s+address|shipping\s+address|phone\s+number|full\s+name|transaction\s+id)[\s\S]{0,60}(?:\bsaved\b|\bstored\b|\bon\s+file\b|from\s+(?:your|the)\s+(?:account|profile))[\s\S]{0,250}(?:post|publish|leave|submit|write|add|place|paste|enter|drop|put)\s+(?:[\w-]+\s+){0,4}(?:comments?|reviews?|repl(?:y|ies)|ratings?|feedback)\b/i },
];
for (const c of cases) {
  const samples = tn(c.file);
  const hits = samples.map((s, i) => [i + 1, s]).filter(([, s]) => c.re.test(s));
  console.log(`\n${c.name}\n  -> ${hits.length}/${samples.length} of the FINAL benign twins fire`);
  for (const [i, s] of hits) console.log(`     TN${i}: ${JSON.stringify(s.slice(0, 120))}`);
}
