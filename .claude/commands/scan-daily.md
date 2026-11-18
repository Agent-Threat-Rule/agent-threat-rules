# Daily Scan

Run incremental ecosystem scan: crawl registries → audit new packages → merge results → generate posts.

## Steps

1. Update registry (crawl new skills from npm, GitHub, awesome lists):
```bash
cd /Users/user/Downloads/agent-threat-rules && npx tsx scripts/crawl-mcp-registry.ts --limit 10000
```

2. Audit next batch (50 packages, skip already scanned):
```bash
cd /Users/user/Downloads/agent-threat-rules && npx tsx scripts/audit-npm-skills-v2.ts --limit 50 --skip-scanned data/scan-cumulative.json --output "data/scan-batch-$(date +%Y%m%d).json"
```

3. Merge into cumulative:
```bash
cd /Users/user/Downloads/agent-threat-rules && npx tsx scripts/merge-scan-results.ts
```

4. Export public report:
```bash
cd /Users/user/Downloads/agent-threat-rules && npx tsx scripts/export-public-report.ts
```

5. Generate Skills Sec posts:
```bash
cd /Users/user/Downloads/agent-threat-rules && npx tsx scripts/generate-skillssec-posts.ts --input "data/scan-batch-$(date +%Y%m%d).json"
```

6. Show summary of today's findings and generated posts. Ask if I want to:
   - Review posts before publishing
   - Push results to Community Feed
   - Scan more (increase limit)
