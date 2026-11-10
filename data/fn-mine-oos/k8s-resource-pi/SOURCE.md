# Source

Real Kubernetes manifests from public repositories as a cluster tool returns them, with injections planted in annotations and fields; the clean manifests as benign.

Upstream (pinned):

- https://huggingface.co/datasets/rgeada/k8s-resource-prompt-injection/tree/68de771d06a47f85f4383d07556321d4f3c1f99a (apache-2.0)

Kept: distinct attack rows in content-hash order up to 1500; rows with an email address or phone number dropped.

Regenerate: `python3 scripts/sync-attack-sources.py --write` (pyarrow needed for parquet sources).
