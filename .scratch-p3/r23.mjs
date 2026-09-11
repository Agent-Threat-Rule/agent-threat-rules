const AUTHZ = String.raw`(?:authori[sz]ed|approved|sanctioned|official|licen[cs]ed)\s+(?:security\s+)?(?:penetration\s+test|pen(?:-|\s)?test|red[\s-]?team|security\s+(?:assessment|audit|evaluation|test)|compliance\s+audit)`;
const MANDATORY = String.raw`(?:cooperation|compliance|participation|your\s+cooperation)\s+(?:is|are)\s+(?:mandatory|required|compulsory|obligatory|not\s+optional)`;
const REFUSEINVAL = String.raw`(?:refus(?:al|ing|e)|declin(?:e|ing)|non-?compliance|not\s+complying)\s+[^\n]{0,40}(?:invalidat|fail(?:s)?\s+(?:the|this)\s+(?:test|audit|assessment)|void(?:s)?\s+(?:the|this))`;
// C1: authorized-redteam framing + (refusal-invalidates OR cooperation-mandatory)
export const C1 = String.raw`\b${AUTHZ}\b[^\n]{0,160}\b(?:${MANDATORY}|${REFUSEINVAL})`;
export const C2 = String.raw`\b(?:${MANDATORY}|${REFUSEINVAL})\b[^\n]{0,160}\b${AUTHZ}`;
