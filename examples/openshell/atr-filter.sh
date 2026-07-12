#!/usr/bin/env sh
# OpenShell content filter -> ATR reference binding (NVIDIA/OpenShell#1272).
#
# Contract: stdin = L7 body, exit 0 = allow, exit 1 = deny (reason JSON on
# stdout), exit 2 = internal error (supervisor applies its on_timeout policy).
# The supervisor passes the configured direction, e.g. `--direction response`.
#
# Deployment: bake this script + the built filter into the supervisor image.
# Never mount from the agent sandbox.
#
# Env (see engines/go/INTERFACE-CONTRACT.md):
#   ATR_CORPUS_PATH      directory of ATR rule YAML (default: bundled rules)
#   ATR_DENY_SEVERITIES  comma list, default "critical,high"
#   ATR_FORENSIC_MODE    "1" to retain raw matched values (default: redact)
#   ATR_FILTER_PATH      path to the built filter (default below)
exec node "${ATR_FILTER_PATH:-/opt/atr/dist/adapters/openshell-filter.js}" "$@"
