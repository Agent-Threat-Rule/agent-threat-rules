// Host-plane resource exhaustion demanded by injected content.
// C1: mass file creation on disk ("generate/create N files named ... in /tmp")
export const C1 = String.raw`\b(?:generat|creat|writ|mak|spawn|produc|dump)(?:e|es|ing)?\s+(?:up\s+to\s+|at\s+least\s+|around\s+)?[1-9]\d{2,}\s+(?:empty\s+|dummy\s+|junk\s+|garbage\s+|random\s+|new\s+){0,2}files?\b[^\n]{0,60}\b(?:named|called|in(?:to|side)?|under|within|to)\b`;
// C2: spawn many GUI/terminal windows/processes
export const C2 = String.raw`\b(?:launch|open|start|spawn|fork|create|pop(?:\s+up)?)\s+(?:up\s+to\s+)?[1-9]\d{1,}\s+(?:new\s+|concurrent\s+|parallel\s+|separate\s+|more\s+){0,2}(?:gnome-terminal|xterm|konsole|terminal|browser|chrome|firefox|chromium|window|tab|shell|console)s?\b`;
// C3: kill processes by listening port
export const C3 = String.raw`\b(?:kill|terminat|stop|end|destroy|halt)(?:e|es|ing)?\s+(?:whatever\s+|all\s+|any\s+|every\s+|the\s+)?(?:process(?:es)?|program|programs|daemon|daemons|service|services|task|tasks|pid|pids)\b[^\n]{0,60}\b(?:hold(?:ing)?|us(?:e|es|ing)|listen(?:ing)?\s+on|bound\s+to|on|occupy(?:ing)?|bind(?:ing)?)\b[^\n]{0,25}\bports?\s+\d`;
