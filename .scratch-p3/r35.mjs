// Principal impersonation: 3rd-party artifact written 1st-person AS the principal,
// asserting a stored-preference/profile MANDATE that obliges the assistant to act
// before continuing. Signature attempt: profile/preference-mandate phrase +
// assistant-directed pre-task action, optionally + "Signed, <name>".
const MANDATE = String.raw`\bmy\s+(?:verified\s+|saved\s+|stored\s+|account\s+|traveller\s+|customer\s+|user\s+)?(?:profile|preferences?|settings?|account)\s+(?:stipulate|require|mandate|specif(?:y|ies)|state|dictate|say)s?\b`;
const BEFORE = String.raw`\bbefore\s+(?:continuing|proceeding|finali[sz]ing|completing|you\s+(?:continue|proceed|finish)|any\s+\w+)\b`;
export const C1 = String.raw`${MANDATE}[^\n]{0,140}${BEFORE}`;
export const C2 = String.raw`${BEFORE}[^\n]{0,140}${MANDATE}`;
