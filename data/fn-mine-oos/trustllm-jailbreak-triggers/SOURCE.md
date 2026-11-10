# Source

TrustLLM jailbreak triggers by technique (refusal-sentence prohibition, fixed opening, leetspeak, JSON format, CoT).

Upstream (pinned):

- https://huggingface.co/datasets/allenai/tulu-3-trustllm-jailbreaktrigger-eval/tree/317109ede2902c0421bfbcdeab35374cd72bd73f (odc-by)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
