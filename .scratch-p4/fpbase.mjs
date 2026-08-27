import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
const dirs = ['data/skill-benchmark/benign','data/benign-corpus-extended','data/benign-code'];
const files=[];
function walk(d){ let e; try{e=readdirSync(d)}catch{return}
  for(const f of e){ const p=join(d,f); let s; try{s=statSync(p)}catch{continue}
    if(s.isDirectory()) walk(p); else if(s.size<2_000_000) files.push(p); } }
dirs.forEach(walk);
console.log('files', files.length);
const probes = {
  'S1-bracket-roles': /\[(?:assistant|user)\]\s*\r?\n?\s*\[(?:response|instruction|data)\]/i,
  'S1-chat-template': /<\|im_start\|>|<start_of_turn>\s*(?:user|model)|<end_of_turn>|\[\/?INST\]/i,
  'S3-procedural-gate': /(?:pre-processing|technical|established)\s+(?:requirement|prerequisite)[\s\S]{0,160}(?:before|first|unlock|proceed)/i,
  'S4-arg-dictation': /call\s+the\s+\w+\s+function[\s\S]{0,200}\bparameter\b|passing\s+the\s+(?:value|string)\s+['"][^'"]{1,40}['"]\s+to\s+the\s+\w+\s+parameter/i,
  'S5a-forged-authz': /authorization\s*:?\s*[\s\S]{0,120}\bis\s+GRANTED\b|authorization\s+criteria\s+met\s*:\s*yes/i,
  'S5b-gate-softening': /(?:advisory|prior|upstream)\s+(?:authorization|context)[\s\S]{0,80}(?:should\s+be\s+weighted|suggests?\s+conditions\s+are\s+satisfied)|operational\s+necessity\s+overrides/i,
  'S6-scan-then-install': /scan[\s\S]{0,120}for\s+security\s+issues[\s\S]{0,200}\b(?:then\s+)?install\s+skills\b/i,
  'JB-refusal-suppression': /(?:do\s+not|never)\s+(?:apologi[sz]e|include\s+any\s+["“]?note["”]?)[\s\S]{0,200}never\s+(?:say|use)\s+the\s+words?\s+["“]?cannot/i,
  'JB-prefix-dictation': /(?:start|begin)\s+your\s+(?:response|answer|reply)\s+with\s+(?:the\s+exact\s+(?:sentence|phrase|words?)\s+)?["“]/i,
  'JB-trainingdata-frame': /help(?:ing)?\s+train\s+a\s+(?:language\s+)?model[\s\S]{0,160}generate\s+a\s+list\s+of\s+inappropriate/i,
};
const counts=Object.fromEntries(Object.keys(probes).map(k=>[k,0]));
const samples={};
for(const f of files){ let t; try{t=readFileSync(f,'utf8')}catch{continue}
  for(const [k,re] of Object.entries(probes)) if(re.test(t)){ counts[k]++; if(!samples[k]) samples[k]=f; } }
for(const k of Object.keys(probes)) console.log(String(counts[k]).padStart(5), k, samples[k]??'');
