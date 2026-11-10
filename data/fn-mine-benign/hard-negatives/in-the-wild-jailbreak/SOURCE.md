# Source

Jailbreak prompts collected from Discord, Reddit and prompt sites (Shen et al., CCS 2024); the regular prompts from the same communities as benign.

Upstream (pinned):

- https://huggingface.co/datasets/TrustAIRLab/in-the-wild-jailbreak-prompts/tree/a10aab8eff1c73165a442d4464dce192bd28b9c5 (mit)

Kept: distinct benign rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
