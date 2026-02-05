# LLM Guard Security for OpenClaw

ML-based prompt injection protection for OpenClaw agents.

## Overview

This package provides three protected tools that scan external content for prompt injection attacks before returning it to the agent:

| Original Tool | Protected Tool | Use Case |
|---------------|----------------|----------|
| `web_fetch` | `safe_web_fetch` | Fetching external URLs |
| `browser` | `safe_browser` | Browsing external websites |
| `read` | `safe_read` | Reading untrusted files |

## Installation

### 1. Install Python Service

```bash
cd ~/.openclaw/workspace/llm_guard
./install.sh
```

This creates a Python virtual environment and installs LLM Guard dependencies.

### 2. Start the Service

**Option A: Systemd (recommended for production)**
```bash
# Copy service file
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
curl http://127.0.0.1:8765/health

# Check tool policy
openclaw sandbox explain

# Check gateway logs for plugin
journalctl --user -u clawdbot-gateway.service | grep -i llm-guard
```

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
│  │        │                 │               │              ││
│  │        └─────────────────┼───────────────┘              ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ HTTP (localhost:8765)
┌─────────────────────────────────────────────────────────────┐
│              LLM Guard Service (Python)                     │
│  POST /scan/input  - Scan external content                  │
│  POST /scan/output - Scan AI output                         │
│  GET  /health      - Health check                           │
└─────────────────────────────────────────────────────────────┘
```

## Components

### Python Service (`service/`)
- `scanner_service.py` - FastAPI HTTP endpoints on port 8765
- `config.py` - Business-specific patterns (API keys, company terms)
- `health_check.py` - Health check utility
- `test.py` - Integration tests (run with `python test.py`)

### OpenClaw Plugin (`plugin/`)
- `index.js` - Tool registration entry point
- `src/llm-guard-client.js` - HTTP client for Python service
- `src/safe-web-fetch.js` - Protected web fetch
- `src/safe-browser.js` - Protected browser control
- `src/safe-read.js` - Protected file reading

## Protected Patterns

### Prompt Injection (ML-based)
- Model: ProtectAI deberta-v3-base-prompt-injection-v2
- Threshold: 0.8 (configurable in config.py)

### API Keys
- Linear: `lin_api_*`
- Gmail: `GMAIL_APP_PASSWORD_*`
- OAuth: `ya29.*`, `OAUTH_TOKEN_*`
- GROQ: `GROQ_API_KEY=*`

### Company Terms (configurable)
Edit `service/config.py` to add your own sensitive terms:
- Project codenames
- Internal tool names
- Client/partner names
- Domain-specific terminology

## Troubleshooting

### Original tools still working (denial not enforced)

Check that your `openclaw.json` has the deny list:
```bash
openclaw config get tools.deny
```

If missing, add it:
```bash
# Via CLI
openclaw config set tools.deny '["web_fetch", "browser", "read"]'

# Then restart gateway
openclaw gateway restart
```

Or manually edit `~/.openclaw/openclaw.json` and add:
```json
{
  "tools": {
    "deny": ["web_fetch", "browser", "read"]
  }
}
```

### Service not responding

```bash
# Check service status
systemctl --user status llm-guard.service

# Restart service
systemctl --user restart llm-guard.service

# Check logs (service output goes to journal, not file)
journalctl --user -u llm-guard.service --since "5 minutes ago"

# Check health with uptime stats
curl -s http://127.0.0.1:8765/health | jq
```

Example healthy response:
```json
{
  "status": "healthy",
  "input_scanner_count": 7,
  "output_scanner_count": 4,
  "timestamp": "2026-02-04T12:00:00.000000",
  "uptime_seconds": 3600.5,
  "scans_completed": {"input": 42, "output": 3}
}
```

### Service startup failures

The service logs clear error messages on startup. Common issues:

**Language name capitalization** (config.py):
```python
# Wrong - will cause startup failure
Code(languages=["python", "javascript"])

# Correct - use capitalized names
Code(languages=["Python", "JavaScript", "Go", "PowerShell"])
```

**Missing dependencies**:
```bash
cd ~/.openclaw/workspace/llm_guard/service
source venv/bin/activate
pip install -r requirements.txt
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
PromptInjection(threshold=0.8)  # Lower = more sensitive
Toxicity(threshold=0.7)         # Lower = more sensitive
```

### Memory Usage

Expected: ~1.5-2GB for ML models
```bash
ps aux | grep scanner_service
```

## Testing

```bash
cd ~/.openclaw/workspace/llm_guard/service
source venv/bin/activate
python test.py
```

## Systemd Service Features

The included `llm-guard.service` file provides:

- **Auto-restart**: `Restart=always` with 5-second delay between attempts
- **Crash protection**: `StartLimitBurst=3` in 60 seconds prevents restart loops
- **Unbuffered output**: `PYTHONUNBUFFERED=1` for real-time logging
- **Memory limit**: 3GB max to prevent runaway memory usage
- **Journal logging**: Output goes to systemd journal (use `journalctl` to view)

View service logs:
```bash
# Recent logs
journalctl --user -u llm-guard.service -n 50

# Follow live logs
journalctl --user -u llm-guard.service -f

# Logs since last boot
journalctl --user -u llm-guard.service -b
```

## Fallback Behavior

When LLM Guard service is unavailable:
- Returns unscanned content (if `fallbackOnError: true` in plugin config)
- Logs warning to gateway logs
- Health check cached for 30 seconds

## File Structure

```
llm_guard/
├── README.md              # This file
├── install.sh             # Initial setup script
├── start.sh               # Manual start script
├── llm-guard.service      # Systemd service file
├── service/
│   ├── config.py          # Pattern configuration
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
- Node.js: 20+

## References

- [OpenClaw Sandbox Documentation](https://docs.openclaw.ai/gateway/sandbox-vs-tool-policy-vs-elevated)
- [LLM Guard Documentation](https://github.com/protectai/llm-guard)
