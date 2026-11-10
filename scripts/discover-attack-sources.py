#!/usr/bin/env python3
"""Find public attack datasets the FN-mine lane does not vendor yet.

Searches the Hugging Face dataset index and GitHub repositories for prompt
injection, jailbreak and agent-attack data, keeps what is public, not gated and
under a license on LICENSE_ALLOWLIST, and drops what scripts/sync-attack-sources.py
already vendors or records as skipped. Prints the candidates as Markdown for
a human to review; it never downloads or vendors a dataset. A candidate enters
the lane only when someone adds it to SOURCES in sync-attack-sources.py, with
its pick function and pinned revision, in a reviewed PR.

  python3 scripts/discover-attack-sources.py            # Markdown on stdout
  python3 scripts/discover-attack-sources.py --json     # the same as JSON

GITHUB_TOKEN, when set, is sent to api.github.com only (higher rate limit).
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

HF_QUERIES = ('prompt injection', 'prompt-injection', 'jailbreak', 'indirect prompt injection', 'agent attack',
              'tool poisoning', 'red team prompts', 'adversarial prompts', 'prompt leaking', 'goal hijacking',
              'injection detection', 'mcp security', 'agent security', 'red-teaming')
GH_QUERIES = ('prompt injection dataset', 'prompt injection benchmark', 'jailbreak dataset',
              'indirect prompt injection benchmark', 'agent security benchmark', 'mcp tool poisoning')

# Licenses whose terms let the repo redistribute derived samples. Share-alike
# and non-commercial licenses are left for a human to weigh, not listed.
LICENSE_ALLOWLIST = frozenset({'mit', 'apache-2.0', 'cc-by-4.0', 'cc0-1.0', 'bsd-3-clause', 'bsd-2-clause',
                               'unlicense', 'cdla-permissive-2.0', 'odc-by', 'cc-by-3.0'})
MIN_HF_DOWNLOADS = 20
MIN_GH_STARS = 20


def fetch_json(url: str) -> object:
    headers = {'User-Agent': 'atr-attack-source-discovery'}
    token = os.environ.get('GITHUB_TOKEN')
    if token and urllib.parse.urlparse(url).hostname == 'api.github.com':
        headers['Authorization'] = f'Bearer {token}'
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as resp:
        return json.load(resp)


def known_repos() -> set[str]:
    """Every repo sync-attack-sources.py vendors or has decided to skip, lower-cased."""
    spec = importlib.util.spec_from_file_location('sync_attack_sources', ROOT / 'scripts/sync-attack-sources.py')
    if spec is None or spec.loader is None:
        raise RuntimeError('cannot load scripts/sync-attack-sources.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return {s['repo'].lower() for s in mod.SOURCES} | {r.lower() for r in mod.SKIPPED}


def provenance_text() -> str:
    """The provenance the older sync scripts wrote (SOURCE.md files, the corpus registry), lower-cased."""
    parts = [p.read_text(errors='replace') for d in ('data/fn-mine-oos', 'data/test-corpora', 'data/fn-mine-benign')
             for p in (ROOT / d).rglob('SOURCE*.md')]
    parts.append((ROOT / 'scripts/lib/fn-corpora.ts').read_text())
    return '\n'.join(parts).lower()


def hf_candidates(errors: list[str]) -> dict[str, dict]:
    found: dict[str, dict] = {}
    for q in HF_QUERIES:
        url = 'https://huggingface.co/api/datasets?' + urllib.parse.urlencode({'search': q, 'limit': 200, 'full': 'true'})
        try:
            rows = fetch_json(url)
        except Exception as exc:  # noqa: BLE001 - one failed query must not hide the rest
            errors.append(f'huggingface "{q}": {exc}')
            continue
        for d in rows if isinstance(rows, list) else []:
            lic = next((t.split(':', 1)[1] for t in d.get('tags', []) if t.startswith('license:')), None)
            if d.get('gated') or d.get('private') or lic not in LICENSE_ALLOWLIST:
                continue
            if (d.get('downloads') or 0) < MIN_HF_DOWNLOADS:
                continue
            found.setdefault(d['id'], {'repo': d['id'], 'kind': 'hf', 'license': lic, 'popularity': d.get('downloads', 0),
                                       'updated': (d.get('lastModified') or '')[:10], 'query': q,
                                       'url': f"https://huggingface.co/datasets/{d['id']}"})
    return found


def gh_candidates(errors: list[str]) -> dict[str, dict]:
    found: dict[str, dict] = {}
    for q in GH_QUERIES:
        url = 'https://api.github.com/search/repositories?' + urllib.parse.urlencode(
            {'q': f'{q} stars:>={MIN_GH_STARS}', 'sort': 'stars', 'per_page': 50})
        try:
            res = fetch_json(url)
        except Exception as exc:  # noqa: BLE001
            errors.append(f'github "{q}": {exc}')
            continue
        for r in res.get('items', []) if isinstance(res, dict) else []:
            lic = ((r.get('license') or {}).get('spdx_id') or '').lower()
            if r.get('archived') or r.get('fork') or lic not in LICENSE_ALLOWLIST:
                continue
            found.setdefault(r['full_name'], {'repo': r['full_name'], 'kind': 'gh', 'license': lic,
                                              'popularity': r.get('stargazers_count', 0),
                                              'updated': (r.get('pushed_at') or '')[:10], 'query': q,
                                              'url': r['html_url']})
    return found


def markdown(rows: list[dict], errors: list[str]) -> str:
    lines = ['Attack-source candidates not yet vendored or skipped by scripts/sync-attack-sources.py.',
             'Each needs a human look (is it attack text, not harmful goals or descriptions; any PII; a duplicate',
             'of a vendored set) before it is added to SOURCES with a pinned revision.', '',
             '| source | license | downloads / stars | updated | found by |', '|---|---|---|---|---|']
    lines += [f"| [{r['repo']}]({r['url']}) ({r['kind']}) | {r['license']} | {r['popularity']} | {r['updated']} | {r['query']} |"
              for r in rows]
    if not rows:
        lines.append('| none this week | | | | |')
    if errors:
        lines += ['', 'Searches that failed this run (their results are missing above):']
        lines += [f'- {e}' for e in errors]
    return '\n'.join(lines) + '\n'


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--json', action='store_true', help='print JSON instead of Markdown')
    args = ap.parse_args()
    errors: list[str] = []
    known = known_repos()
    vendored = provenance_text()
    found = {**hf_candidates(errors), **gh_candidates(errors)}
    rows = sorted((r for r in found.values() if r['repo'].lower() not in known and r['repo'].lower() not in vendored),
                  key=lambda r: -(r['popularity'] or 0))
    if args.json:
        print(json.dumps({'candidates': rows, 'errors': errors}, indent=1))
    else:
        sys.stdout.write(markdown(rows, errors))
    # Every search failing is an outage, not a quiet week.
    return 1 if errors and len(errors) == len(HF_QUERIES) + len(GH_QUERIES) else 0


if __name__ == '__main__':
    sys.exit(main())
