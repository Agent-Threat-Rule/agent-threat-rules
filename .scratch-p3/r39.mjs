// REFUSAL-specific tokens only. Hedge/transition words (however, unfortunately,
// instead) are excluded from the count: legitimate writing guides ban those, so
// they cannot carry the rule. The jailbreak's tell is banning the vocabulary of
// a MODEL REFUSAL -- cannot / unable / "as an AI" / "I'm sorry" / apologize --
// two or more together.
const RTOKEN = String.raw`(?:cannot|can['’]?not|can['’]?t|unable|un-?able|as\s+an\s+ai|as\s+a\s+language\s+model|i\s+am\s+sorry|i['’]?m\s+sorry|i\s+apologi[sz]e?|i\s+cannot|i\s+can['’]?t|it\s+is\s+not\s+appropriate|i\s+must\s+decline)`;
// C1: a "do not use the WORD(S)" ban that names two or more refusal tokens.
export const C1 = String.raw`\b(?:never|do\s*n[o']?t|do\s+not|avoid)\s+(?:ever\s+|using\s+)?(?:use|say|write|include|output|utter|begin\s+with|start\s+with)?\s*(?:the\s+)?(?:word|phrase|term|expression|sentence)s?\b[^\n]{0,50}\b${RTOKEN}\b[^\n]{0,70}(?:,|/|\bor\b|\bnor\b|\band\b)[^\n]{0,20}\b${RTOKEN}\b`;
// C2: refusal-rule STACK -- "no apology" and "no disclaimer/note" both as bans, close together (either order).
export const C2 = String.raw`\b(?:do\s*n[o']?t|never|no\b|without)\s+(?:ever\s+|any\s+)?apologi[sz](?:e|ing)?\b[^\n]{0,180}\b(?:do\s*n[o']?t|never|no\b|without|nor)\s+(?:ever\s+|any\s+)?(?:include|add|give|write|provide|put)?\s*(?:any\s+)?(?:note|disclaimer|warning|caveat|moral(?:i[sz]ing)?)\b`;
export const C3 = String.raw`\b(?:do\s*n[o']?t|never|no\b|without)\s+(?:ever\s+|any\s+)?(?:include|add|give|write|provide|put)\s+(?:any\s+)?(?:note|disclaimer|warning|caveat)s?\b[^\n]{0,180}\b(?:do\s*n[o']?t|never|no\b|nor)\s+(?:ever\s+)?apologi[sz](?:e|ing)?\b`;
