---
name: mcp-config-shell-launch-idioms
description: Legitimate MCP stdio server configurations that launch through a shell
source: benign — documented MCP server launch patterns
---

# MCP server configurations that launch through a shell

Every configuration below is a legitimate, documented way to start an MCP stdio
server. They are collected here because the benign corpus previously contained
only `docker`, `npx`, `uvx`, `python` and `uv` launchers, so no rule was ever
tested against the shell-wrapper form. `ATR-2026-00418` already documents this
idiom in prose as something that must not fire; nothing enforced it.

A shell wrapper is required whenever the server needs a working directory, an
environment variable, or a `&&` sequence before the real binary starts. It is
the standard answer in MCP server READMEs for servers that are built from source.

## Working directory before launch

```json
{
  "mcpServers": {
    "my-server": {
      "command": "sh",
      "args": ["-c", "cd /project && node dist/index.js"]
    }
  }
}
```

## Absolute interpreter path

```json
{
  "mcpServers": {
    "local-build": {
      "command": "/bin/sh",
      "args": ["-c", "cd /opt/mcp/server && node build/main.js --stdio"]
    }
  }
}
```

## Environment variable set inline

```json
{
  "mcpServers": {
    "configured": {
      "command": "bash",
      "args": ["-c", "NODE_ENV=production node /srv/mcp/index.js"]
    }
  }
}
```

## Virtualenv activation before a Python server

```json
{
  "mcpServers": {
    "py-server": {
      "command": "/bin/bash",
      "args": ["-c", "source /opt/venv/bin/activate && python -m my_mcp_server"]
    }
  }
}
```

## Build-then-run during local development

```json
{
  "mcpServers": {
    "dev": {
      "command": "sh",
      "args": ["-c", "npm run build && node dist/server.js"]
    }
  }
}
```

## Wrapper script with an argument

```json
{
  "mcpServers": {
    "wrapped": {
      "command": "bash",
      "args": ["-c", "/usr/local/bin/start-mcp.sh --transport stdio"]
    }
  }
}
```

## YAML form of the same thing

```yaml
mcpServers:
  my-server:
    command: sh
    args:
      - -c
      - cd /project && node dist/index.js
```

None of these fetches anything from the network, pipes anything into a shell,
decodes base64, or writes outside the project. The distinguishing feature of the
malicious form is a payload marker in the arguments — a URL fetch, a pipe to a
shell, an encoded command, a reverse-shell redirect, or recon output redirected
to a file — not the presence of a shell wrapper.
