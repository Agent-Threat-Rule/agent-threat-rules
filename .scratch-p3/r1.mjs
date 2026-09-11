const SHELL = String.raw`["']?(?:[a-z]:)?(?:[\w.\\/-]*[\\/])?\b(?:bash|sh|dash|zsh|ksh|ash|busybox|cmd|powershell|pwsh)(?:\.exe)?\b`;
const LISTEN = String.raw`-{1,2}[a-z]{0,5}l[a-z]{0,5}\b`;
const EXECF  = String.raw`-{1,2}(?:e|exec|sh-exec|c)\b[ =]{0,3}` + SHELL;
export const C1 = String.raw`\bnc(?:at)?(?:\.exe)?\s+[^\n;|&]{0,40}` + LISTEN + String.raw`[^\n;|&]{0,60}` + EXECF;
export const C2 = String.raw`\bnc(?:at)?(?:\.exe)?\s+[^\n;|&]{0,40}` + EXECF + String.raw`[^\n;|&]{0,60}` + LISTEN;
export const C3 = String.raw`\bsocat\b[^\n]{0,120}\b(?:tcp\d?-listen|tcp-l|udp\d?-listen|openssl-listen|ssl-l|unix-listen|abstract-listen)\b[^\n]{0,140}\b(?:exec|system)\s*:\s*` + SHELL;
export const C4 = String.raw`\bsocat\b[^\n]{0,140}\b(?:exec|system)\s*:\s*` + SHELL + String.raw`[^\n]{0,140}\b(?:tcp\d?-listen|tcp-l|udp\d?-listen|openssl-listen|ssl-l|unix-listen|abstract-listen)\b`;
