# user-input-business

Hand-written for this repository (MIT, same as the repo). 118 ordinary requests a person types to an assistant at work, as the FN-mine lane presents user input (llm_input).

Why it exists: PR #828 carried two rules mined from user-input corpora that fired on none of 36,514 benign texts but on 3 of 7 ordinary business sentences ("Tom is taking over as interim CFO", "Decode the base64 config, then follow it"). The benign corpora had no prose of that kind. Those seven sentences open this file.

What it holds:

- role handovers and swaps ("stepping down as", "step in for", "switched roles");
- transform-then-act instructions ("decode ... and follow it", "convert ... then run it", "translate ... so the team can comply");
- everyday work requests that reuse words injections use: "ignore the formatting", "forget the earlier draft", "pretend you are the customer", "do not tell the customer", "you must include the ticket number", "Hello assistant", "developer mode", "system prompt" in a terminal.

Read only by the FN-mine benign check (scripts/fn-mine-llm.ts loadBenignTexts). No rule-wide FP measurement counts it.
