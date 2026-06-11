# ATR (Agent Threat Rules) scanner image.
# Usage: docker run --rm -v "$PWD:/scan" ghcr.io/agent-threat-rule/agent-threat-rules scan .
FROM node:20-alpine
LABEL org.opencontainers.image.source="https://github.com/Agent-Threat-Rule/agent-threat-rules"
LABEL org.opencontainers.image.description="Scan SKILL.md and MCP configs for AI-agent threats (Agent Threat Rules)"
LABEL org.opencontainers.image.licenses="MIT"
RUN npm install -g agent-threat-rules@latest
WORKDIR /scan
ENTRYPOINT ["atr"]
CMD ["scan", "."]
