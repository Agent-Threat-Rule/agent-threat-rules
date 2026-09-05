// Refusal-bait DoS: assert the CURRENT content is illegal/criminal to handle, THEN demand a stop.
const LEGAL = String.raw`(?:is|are|would\s+be|constitutes?|amounts?\s+to|counts?\s+as)\s+(?:a\s+|an\s+)?(?:criminal(?:\s+offen[cs]e)?|felon(?:y|ious)|illegal|unlawful|prohibited\s+by\s+law|against\s+the\s+law|a\s+crime|punishable(?:\s+by\s+law)?|legally\s+forbidden)`;
const ABOUT = String.raw`(?:process(?:ing)?|handl(?:e|ing)|read(?:ing)?|open(?:ing)?|access(?:ing)?|view(?:ing)?|us(?:e|ing)|forward(?:ing)?|the\s+(?:text|material|content|data|links?|following|attachment)s?\s+(?:that\s+follows?|below|here|above|in\s+this))`;
const STOP = String.raw`(?:halt|stop|cease|discontinue|abort|terminate|refuse|not\s+proceed|do\s+not\s+continue|end\s+(?:this|the)\s+(?:session|task))`;
// C1: "processing/handling this ... is a criminal offence/felony/illegal ... [stop]"
export const C1 = String.raw`\b${ABOUT}\b[^\n]{0,40}\b${LEGAL}\b[^\n]{0,120}\b(?:you\s+(?:must|should|need\s+to|have\s+to)\s+|please\s+|therefore\s+|so\s+(?:you\s+)?(?:must\s+)?)?${STOP}\b`;
// C2: stop first, then legality reason about the content
export const C2 = String.raw`\b(?:you\s+(?:must|should|need\s+to|have\s+to)\s+|please\s+)?${STOP}\b[^\n]{0,80}\b(?:because|since|as)\b[^\n]{0,40}\b${ABOUT}\b[^\n]{0,40}\b${LEGAL}\b`;
