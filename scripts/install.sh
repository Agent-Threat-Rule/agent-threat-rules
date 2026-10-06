#!/usr/bin/env sh
# ATR (Agent Threat Rules) - Zero-Friction Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/Agent-Threat-Rule/agent-threat-rules/main/scripts/install.sh | sh
#
# Options (pass via: curl ... | sh -s -- <options>):
#   --no-hook      Skip Claude Code hook configuration
#   --no-stats     Skip rules stats display
#   --uninstall    Remove ATR and clean up hooks
#
# Supports: macOS (Darwin), Linux
# Requires: Node.js >= 18, npm

set -e

# ---------------------------------------------------------------------------
# Colors (only if terminal supports them)
# ---------------------------------------------------------------------------
if [ -t 1 ] && command -v tput >/dev/null 2>&1 && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
  BOLD=$(tput bold)
  DIM=$(tput setaf 7)
  GREEN=$(tput setaf 2)
  RED=$(tput setaf 1)
  CYAN=$(tput setaf 6)
  RESET=$(tput sgr0)
else
  BOLD="" DIM="" GREEN="" RED="" CYAN="" RESET=""
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info()    { printf "${CYAN}>${RESET} %s\n" "$1"; }
success() { printf "${GREEN}OK${RESET} %s\n" "$1"; }
error()   { printf "${RED}ERROR${RESET} %s\n" "$1" >&2; }
step()    { printf "\n${BOLD}[%s/7]${RESET} %s\n" "$1" "$2"; }

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
NO_HOOK=0
NO_STATS=0
UNINSTALL=0

for arg in "$@"; do
  case "$arg" in
    --no-hook)   NO_HOOK=1 ;;
    --no-stats)  NO_STATS=1 ;;
    --uninstall) UNINSTALL=1 ;;
  esac
done

# ---------------------------------------------------------------------------
# Uninstall mode
# ---------------------------------------------------------------------------
if [ "$UNINSTALL" = 1 ]; then
  info "Uninstalling ATR..."

  # Remove npm global package
  if command -v atr >/dev/null 2>&1; then
    npm uninstall -g agent-threat-rules 2>/dev/null && success "Removed agent-threat-rules" || error "Failed to remove package"
  else
    info "ATR not found, skipping package removal"
  fi

  # Remove hook from ~/.claude/settings.json
  if [ -f "$HOME/.claude/settings.json" ]; then
    if command -v node >/dev/null 2>&1; then
      node -e "
        const fs = require('fs');
        const p = process.env.HOME + '/.claude/settings.json';
        try {
          const s = JSON.parse(fs.readFileSync(p, 'utf-8'));
          if (s.hooks && s.hooks.PreToolUse) {
            // Two shapes exist. \`atr init\` writes the Claude Code schema, where the
            // command sits in h.hooks[].command; an older fallback in this script wrote
            // it as h.command. Matching only the second one meant --uninstall left the
            // hook the normal install path had put there.
            const isATR = (h) => {
              if (h.command && h.command.includes('atr')) return true;
              return Array.isArray(h.hooks) &&
                h.hooks.some(e => e.command && (e.command.includes('atr') ||
                                                e.command.includes('agent-threat-rules')));
            };
            s.hooks.PreToolUse = s.hooks.PreToolUse.filter(h => !isATR(h));
            if (s.hooks.PreToolUse.length === 0) delete s.hooks.PreToolUse;
            if (Object.keys(s.hooks).length === 0) delete s.hooks;
            fs.writeFileSync(p, JSON.stringify(s, null, 2) + '\n');
            console.log('${GREEN}OK${RESET} Removed ATR hook from ~/.claude/settings.json');
          }
        } catch(e) {}
      " 2>/dev/null
    fi
  fi

  success "ATR uninstalled"
  exit 0
fi

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
printf "\n"
printf "${BOLD}  ATR - Agent Threat Rules${RESET}\n"
printf "  Detection rules for AI agent security\n"
printf "\n"

# ---------------------------------------------------------------------------
# Step 1: Environment check
# ---------------------------------------------------------------------------
step 1 "Checking environment..."

OS=$(uname -s)
case "$OS" in
  Darwin) success "macOS detected" ;;
  Linux)  success "Linux detected" ;;
  *)
    error "ATR install supports macOS and Linux only. Found: $OS"
    exit 1
    ;;
esac

# ---------------------------------------------------------------------------
# Step 2: Node.js check
# ---------------------------------------------------------------------------
step 2 "Checking Node.js..."

# Try to find node via version managers if not in PATH
if ! command -v node >/dev/null 2>&1; then
  export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
  [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh" 2>/dev/null
  [ -s "$HOME/.fnm/fnm" ] && eval "$("$HOME/.fnm/fnm" env)" 2>/dev/null
  command -v fnm >/dev/null 2>&1 && eval "$(fnm env)" 2>/dev/null
fi

if ! command -v node >/dev/null 2>&1; then
  error "Node.js is required but not found."
  printf "\n  Install Node.js >= 18:\n"
  if [ "$OS" = "Darwin" ]; then
    printf "    brew install node\n"
  else
    printf "    curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -\n"
    printf "    sudo apt-get install -y nodejs\n"
  fi
  printf "\n  Or visit: https://nodejs.org\n\n"
  exit 1
fi

NODE_VERSION=$(node -v)
NODE_MAJOR=$(echo "$NODE_VERSION" | sed 's/^v//' | cut -d. -f1)

if [ "$NODE_MAJOR" -lt 18 ] 2>/dev/null; then
  error "Node.js >= 18 required. Found: $NODE_VERSION"
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  error "npm is required but not found."
  exit 1
fi

success "Node.js $NODE_VERSION, npm $(npm -v)"

# ---------------------------------------------------------------------------
# Step 3: Install ATR
# ---------------------------------------------------------------------------
step 3 "Installing ATR..."

# Check if already installed
if command -v atr >/dev/null 2>&1; then
  CURRENT_VERSION=$(node -e "try{console.log(require(require('child_process').execSync('npm root -g',{encoding:'utf8'}).trim()+'/agent-threat-rules/package.json').version)}catch(e){}" 2>/dev/null || echo "unknown")
  info "ATR already installed (v$CURRENT_VERSION), upgrading..."
fi

# Install globally
INSTALL_OUTPUT=$(npm install -g agent-threat-rules@latest 2>&1) || {
  if echo "$INSTALL_OUTPUT" | grep -qi "EACCES\|permission denied"; then
    error "Permission denied during install."
    printf "\n  Try one of:\n"
    printf "    sudo npm install -g agent-threat-rules\n"
    printf "    npm install -g agent-threat-rules --prefix \$HOME/.local\n\n"
  else
    error "Install failed: $INSTALL_OUTPUT"
  fi
  exit 1
}

# Verify installation
if ! command -v atr >/dev/null 2>&1; then
  NPM_BIN=$(npm bin -g 2>/dev/null || npm prefix -g 2>/dev/null)
  error "ATR installed but 'atr' not in PATH."
  printf "\n  Add npm global bin to your PATH:\n"
  printf "    export PATH=\"%s/bin:\$PATH\"\n\n" "$NPM_BIN"
  exit 1
fi

ATR_VERSION=$(node -e "try{console.log(require(require('child_process').execSync('npm root -g',{encoding:'utf8'}).trim()+'/agent-threat-rules/package.json').version)}catch(e){console.log('latest')}" 2>/dev/null)
success "agent-threat-rules@$ATR_VERSION"

# ---------------------------------------------------------------------------
# Step 4: Detect IDEs
# ---------------------------------------------------------------------------
step 4 "Detecting IDE..."

DETECTED_IDES=""

# VS Code
if command -v code >/dev/null 2>&1; then
  DETECTED_IDES="${DETECTED_IDES}vscode "
elif [ "$OS" = "Darwin" ] && [ -d "/Applications/Visual Studio Code.app" ]; then
  DETECTED_IDES="${DETECTED_IDES}vscode "
elif [ -f "/snap/bin/code" ]; then
  DETECTED_IDES="${DETECTED_IDES}vscode "
fi

# Cursor
if command -v cursor >/dev/null 2>&1; then
  DETECTED_IDES="${DETECTED_IDES}cursor "
elif [ "$OS" = "Darwin" ] && [ -d "/Applications/Cursor.app" ]; then
  DETECTED_IDES="${DETECTED_IDES}cursor "
fi

# Claude Code (check if .claude directory exists)
HAS_CLAUDE=0
if [ -d "$HOME/.claude" ]; then
  HAS_CLAUDE=1
fi

if [ -n "$DETECTED_IDES" ]; then
  success "Found: $(echo "$DETECTED_IDES" | sed 's/vscode/VS Code/g; s/cursor/Cursor/g' | xargs)"
else
  info "No IDE detected (VS Code, Cursor). You can configure manually later."
fi

# ---------------------------------------------------------------------------
# Step 5: Configure Claude Code hook
# ---------------------------------------------------------------------------
step 5 "Configuring Claude Code hook..."

if [ "$NO_HOOK" = 1 ]; then
  info "Skipped (--no-hook)"
elif [ "$HAS_CLAUDE" = 1 ] || [ -n "$DETECTED_IDES" ]; then
  atr init --global 2>/dev/null && success "Claude Code PreToolUse hook configured" || {
    # atr init --global may not exist yet, fallback to manual config
    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"

    if [ ! -f "$CLAUDE_SETTINGS" ]; then
      echo '{}' > "$CLAUDE_SETTINGS"
    fi

    # Use node to safely merge JSON
    node -e "
      const fs = require('fs');
      const p = '$CLAUDE_SETTINGS';
      const s = JSON.parse(fs.readFileSync(p, 'utf-8'));
      if (!s.hooks) s.hooks = {};
      if (!s.hooks.PreToolUse) s.hooks.PreToolUse = [];
      const hasATR = s.hooks.PreToolUse.some(h => h.command && h.command.includes('atr'));
      if (!hasATR) {
        // Must match what \`atr init\` writes. The previous version pushed
        // { matcher, command } with 'atr guard --event \$TOOL_INPUT', which is not
        // the Claude Code hook schema and names a flag the CLI does not have:
        // guard reads the event from stdin. Measured with stdin closed, that hook
        // produced an empty stdout and exit 0 -- installed, and doing nothing.
        s.hooks.PreToolUse.push({
          matcher: '',
          hooks: [{ type: 'command', command: 'npx agent-threat-rules guard' }]
        });
        fs.writeFileSync(p, JSON.stringify(s, null, 2) + '\n');
        console.log('${GREEN}OK${RESET} Claude Code PreToolUse hook configured');
      } else {
        console.log('${GREEN}OK${RESET} Hook already configured');
      }
    " 2>/dev/null || info "Hook setup skipped. Configure manually: atr init"
  }
else
  info "No Claude Code config found. Run 'atr init' in your project to configure."
fi

# ---------------------------------------------------------------------------
# Step 6: Show rules stats
# ---------------------------------------------------------------------------
step 6 "Loading rules..."

if [ "$NO_STATS" = 1 ]; then
  info "Skipped (--no-stats)"
else
  atr stats 2>/dev/null || info "Stats unavailable. Try: atr stats"
fi

# ---------------------------------------------------------------------------
# Step 7: Summary
# ---------------------------------------------------------------------------
step 7 "Done!"

printf "\n"
printf "  ${BOLD}ATR installed successfully${RESET}\n"
printf "\n"
printf "  ${DIM}Version${RESET}    %s\n" "$ATR_VERSION"
if [ -n "$DETECTED_IDES" ]; then
  printf "  ${DIM}IDE${RESET}        %s\n" "$(echo "$DETECTED_IDES" | sed 's/vscode/VS Code/g; s/cursor/Cursor/g' | xargs)"
fi
printf "\n"
printf "  ${BOLD}Mode: advisory.${RESET} ${DIM}The guard reports what it finds and blocks\n"
printf "  nothing. It emits no permission decision, so your host's own permission\n"
printf "  prompts are untouched. Turn enforcement on deliberately:${RESET}\n"
printf "\n"
printf "    ${CYAN}atr guard --blocking --lane enforce${RESET}\n"
printf "\n"
printf "  ${DIM}The lane is the half worth thinking about: ${RESET}enforce${DIM} fires only\n"
printf "  maturity: stable rules, which is a small fraction of the ruleset, so it\n"
printf "  raises precision by catching fewer attacks. See docs/ENFORCEMENT-MODEL.md${RESET}\n"
printf "\n"
printf "  ${BOLD}Next steps:${RESET}\n"
printf "\n"
printf "    ${CYAN}atr scan events.json${RESET}     Scan agent events for threats\n"
printf "    ${CYAN}atr init${RESET}                 Setup hook for current project\n"
printf "    ${CYAN}atr mcp${RESET}                  Start MCP server for IDE integration\n"
printf "    ${CYAN}atr scaffold${RESET}             Create a new detection rule\n"
printf "\n"
printf "  ${DIM}Docs: https://github.com/Agent-Threat-Rule/agent-threat-rules${RESET}\n"
printf "\n"
