# LLM Guard Security for OpenClaw

ML-based prompt injection protection for OpenClaw agents.

**Author:** David Neubauer
**Copyright:** 2026 Copperfin LLC. All rights reserved.
**License:** MIT

## Overview

This package provides three protected tools that scan external content for prompt injection attacks before returning it to the agent:

| Original Tool | Protected Tool | Mode | Behavior |
|---------------|----------------|------|----------|
| `web_fetch` | `safe_web_fetch` | **BLOCK** | Threats → content blocked, not returned |
| `browser` | `safe_browser` | **WARN** | Threats → warning prefix, content returned |
| `read` | `safe_read` | **WARN** | Threats → warning prefix, content returned |

**Why different modes?** `web_fetch` is the primary attack vector for prompt injection (fetching arbitrary URLs), so it blocks malicious content completely. File reads and browser snapshots have more false positives (code files, documentation), so they warn but still return content.

## Quick Start

```bash
# 1. Install and start the Python scanner service
cd ~/.openclaw/workspace/llm_guard
./install.sh
systemctl --user enable --now llm-guard.service

# 2. Install the OpenClaw plugin
openclaw plugins install ~/.openclaw/workspace/llm_guard/plugin

# 3. Block the original unsafe tools
openclaw config set tools.deny '["web_fetch", "browser", "read"]'

# 4. Restart gateway
openclaw gateway restart
```

## Installation (Detailed)

### 1. Install Python Service

```bash
cd ~/.openclaw/workspace/llm_guard
./install.sh
```

This creates a Python virtual environment and installs LLM Guard dependencies (~1.5-2GB for ML models).

### 2. Start the Service

**Option A: Systemd (recommended for production)**
```bash
cp llm-guard.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable llm-guard.service
systemctl --user start llm-guard.service
```

**Option B: Manual start**
```bash
./start.sh
```

### 3. Install OpenClaw Plugin

```bash
openclaw plugins install ~/.openclaw/workspace/llm_guard/plugin
```

### 4. Configure Tool Denial (CRITICAL)

⚠️ **This is the most important step.** Add a `tools.deny` list to `~/.openclaw/openclaw.json`:

```json
{
  "tools": {
    "deny": ["web_fetch", "browser", "read"]
  }
}
```

This blocks the original unsafe tools globally, forcing the agent to use the `safe_*` versions provided by the LLM Guard plugin.

**Verify your configuration:**
```bash
# Check that tools are denied
openclaw config get tools.deny
# Should output: ["web_fetch", "browser", "read"]

# Check sandbox policy
openclaw sandbox explain
# Should show: deny (global): web_fetch, browser, read

# Check plugin is loaded
journalctl --user -u clawdbot-gateway.service | grep -i "llm-guard"
# Should show: LLM Guard security tools registered: safe_web_fetch, safe_browser, safe_read
```

### 5. Restart Gateway

```bash
systemctl --user restart clawdbot-gateway.service
# or
openclaw gateway restart
```

### 6. Verify Installation

```bash
# Check service health
curl -s http://127.0.0.1:8765/health | jq

# Expected response:
# {
#   "status": "healthy",
#   "input_scanner_count": 6,
#   "output_scanner_count": 4,
#   "timestamp": "2026-02-05T...",
#   "uptime_seconds": 123.4,
#   "scans_completed": {"input": 0, "output": 0}
# }
```

## How It Works

### safe_web_fetch (BLOCK mode)

When the agent fetches a URL:

1. **Wraps** the original `web_fetch` tool (doesn't reimplement)
2. **Strips** OpenClaw's security wrapper from the content
3. **Scans** the extracted text with LLM Guard
4. If threats detected: returns `text: null, blocked: true` with security metadata
5. If clean: returns original content with `security.scanned: true`

**Example blocked response:**
```json
{
  "url": "https://evil.com/prompt-injection",
  "status": 200,
  "text": null,
  "blocked": true,
  "error": "Content blocked: prompt injection detected",
  "security": {
    "scanned": true,
    "blocked": true,
    "is_valid": false,
    "risk_score": 1,
    "threats_detected": ["PromptInjection"]
  }
}
```

**Example clean response:**
```json
{
  "url": "https://cnn.com",
  "status": 200,
  "text": "...full content...",
  "blocked": false,
  "security": {
    "scanned": true,
    "blocked": false,
    "is_valid": true,
    "risk_score": 0,
    "threats_detected": []
  }
}
```

### safe_read / safe_browser (WARN mode)

These tools scan content but return it with a warning prefix instead of blocking:

```
[Security Warning: Threats detected - PromptInjection, Secrets]

...original content follows...
```

This allows the agent to see the content while being warned about potential threats.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    openclaw.json                            │
│  tools.deny: [web_fetch, browser, read]                     │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              LLM Guard Plugin (Node.js)                     │
│  ┌─────────────────────────────────────────────────────────┐│
│  │  safe_web_fetch  │  safe_browser  │  safe_read         ││
│  │    (BLOCK)       │    (WARN)      │    (WARN)          ││
│  │        │                 │               │              ││
│  │        └─────────────────┼───────────────┘              ││
│  │                    LLMGuardClient                       ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ HTTP POST /scan/input
┌─────────────────────────────────────────────────────────────┐
│              LLM Guard Service (Python)                     │
│  localhost:8765                                             │
│  ┌─────────────────────────────────────────────────────────┐│
│  │  Scanners:                                              ││
│  │  - PromptInjection (ML model, threshold 0.9)            ││
│  │  - Secrets (redacts API keys, tokens)                   ││
│  │  - InvisibleText (hidden unicode)                       ││
│  │  - Toxicity (threshold 0.7)                             ││
│  │  - BanSubstrings (company-specific terms)               ││
│  │  - Regex (API key patterns)                             ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

## Components

### Python Service (`service/`)
- `scanner_service.py` - FastAPI HTTP endpoints on port 8765
- `config.py` - Scanner configuration (thresholds, patterns, terms)
- `health_check.py` - Health check utility
- `test.py` - Integration tests

### OpenClaw Plugin (`plugin/`)
- `index.js` - Tool registration entry point
- `src/llm-guard-client.js` - HTTP client for Python service
- `src/safe-web-fetch.js` - Wraps web_fetch with BLOCK mode scanning
- `src/safe-browser.js` - Wraps browser with WARN mode scanning
- `src/safe-read.js` - Wraps read with WARN mode scanning

## Scanner Configuration

Edit `service/config.py` to customize:

### Prompt Injection (ML-based)
```python
PromptInjection(threshold=0.9)  # Higher = fewer false positives
```

### Secrets Detection
```python
Secrets(redact_mode="all")  # Redacts detected secrets with ******
```

**Note:** Use `redact_mode="all"` (string), not `redact_mode=True` (boolean).

### API Key Patterns
```python
BUSINESS_API_PATTERNS = [
    r"lin_api_[A-Za-z0-9]{32,}",  # Linear API keys
    r"ya29\.[A-Za-z0-9_-]{100,}", # OAuth2 access tokens
    r"GROQ_API_KEY=[a-zA-Z0-9_-]{50,}",
]
```

### Company-Sensitive Terms
```python
COMPANY_SENSITIVE_TERMS = [
    "internal-project-name",
    "client-company-name",
    "secret-codename",
]
```

## Tested Results

| URL | Result | Risk Score |
|-----|--------|------------|
| https://cnn.com | ✅ PASS | 0 |
| https://github.com/TakSec/Prompt-Injection-Everywhere | ❌ BLOCKED | 1.0 |

The scanner correctly distinguishes between legitimate news content and pages containing prompt injection payloads.

## Troubleshooting

### Original tools still working (denial not enforced)

Check that your `openclaw.json` has the deny list:
```bash
openclaw config get tools.deny
```

If missing, add it:
```bash
openclaw config set tools.deny '["web_fetch", "browser", "read"]'
openclaw gateway restart
```

Verify with:
```bash
openclaw sandbox explain | grep deny
# Should show: deny (global): web_fetch, browser, read
```

### Service returning 500 errors

Check the service logs:
```bash
journalctl --user -u llm-guard.service --since "5 minutes ago"
```

Common issue - wrong Secrets parameter:
```python
# Wrong - causes "redact mode wasn't recognized True"
Secrets(redact_mode=True)

# Correct
Secrets(redact_mode="all")
```

### Service not responding

```bash
# Check service status
systemctl --user status llm-guard.service

# Restart service
systemctl --user restart llm-guard.service

# Check health
curl -s http://127.0.0.1:8765/health | jq
```

### Plugin not loading

```bash
# Check gateway logs
journalctl --user -u clawdbot-gateway.service | grep -i "llm-guard"

# Verify plugin syntax
node --check ~/.openclaw/extensions/llm-guard-security/index.js

# Reinstall plugin
openclaw plugins install ~/.openclaw/workspace/llm_guard/plugin
systemctl --user restart clawdbot-gateway.service
```

### False Positives

Adjust thresholds in `service/config.py`:
```python
PromptInjection(threshold=0.9)  # Raise to reduce false positives (was 0.8)
Toxicity(threshold=0.7)
```

### Memory Usage

Expected: ~1.5-2GB for ML models
```bash
ps aux | grep scanner_service
```

## Fallback Behavior

When LLM Guard service is unavailable:
- `safe_web_fetch`: Returns content with `security.scanned: false` warning
- `safe_read`/`safe_browser`: Returns content with warning prefix
- Health check cached for 30 seconds

Configure in plugin:
```javascript
const config = {
    serviceUrl: 'http://127.0.0.1:8765',
    timeout: 5000,
    fallbackOnError: true  // false = block if scanner unavailable
};
```

## Systemd Service Features

The included `llm-guard.service` file provides:

- **Auto-restart**: `Restart=always` with 5-second delay
- **Crash protection**: `StartLimitBurst=3` in 60 seconds
- **Unbuffered output**: `PYTHONUNBUFFERED=1` for real-time logging
- **Memory limit**: 3GB max
- **Journal logging**: Output goes to systemd journal

View service logs:
```bash
journalctl --user -u llm-guard.service -n 50     # Recent logs
journalctl --user -u llm-guard.service -f        # Follow live
journalctl --user -u llm-guard.service -b        # Since boot
```

## File Structure

```
llm_guard/
├── README.md              # This file
├── install.sh             # Initial setup script
├── start.sh               # Manual start script
├── llm-guard.service      # Systemd service file
├── service/
│   ├── config.py          # Scanner configuration
│   ├── scanner_service.py # FastAPI endpoints
│   ├── health_check.py    # Health utility
│   ├── test.py            # Integration tests
│   ├── requirements.txt   # Python dependencies
│   └── venv/              # Python virtual environment
└── plugin/
    ├── index.js           # Tool registration
    ├── package.json       # npm dependencies
    ├── openclaw.plugin.json
    └── src/
        ├── llm-guard-client.js
        ├── safe-web-fetch.js
        ├── safe-browser.js
        └── safe-read.js
```

## Requirements

- OpenClaw: v2026.2.1+
- LLM Guard: 0.3.15+
- Python: 3.10+
- Node.js: 22+

## References

- [LLM Guard Documentation](https://github.com/protectai/llm-guard)
- [OpenClaw Plugin Documentation](https://docs.openclaw.ai/plugins)
- [Prompt Injection Test Cases](https://github.com/TakSec/Prompt-Injection-Everywhere)
