# OpenClaw 的 LLM Guard 安全插件（中文版）

为 OpenClaw 代理提供基于机器学习的提示注入防护。

作者：David Neubauer  
版权：© 2026 [Copperfin LLC](https://www.copperfin.io/)  
许可证：MIT

底层依赖 [Protect AI 的 LLM Guard](https://github.com/protectai/llm-guard)。

## 概览

本项目提供 3 个安全包装工具，会在把外部内容返回给代理前先做安全扫描：

| 原始工具 | 安全工具 | 模式 | 行为 |
|---|---|---|---|
| `web_fetch` | `safe_web_fetch` | **BLOCK** | 命中威胁则拦截，不返回正文 |
| `browser` | `safe_browser` | **WARN** | 命中威胁则加警告前缀，但仍返回内容 |
| `read` | `safe_read` | **WARN** | 命中威胁则加警告前缀，但仍返回内容 |

为什么模式不同：`web_fetch` 是最常见的注入入口（抓任意 URL），默认直接阻断更稳；`read/browser` 在代码和文档场景误报更常见，因此采用告警返回。

## 快速开始

```bash
# 1) 安装并启动 Python 扫描服务
cd ~/.openclaw/workspace/llm_guard
./install.sh
systemctl --user enable --now llm-guard.service

# 2) 安装 OpenClaw 插件
openclaw plugins install ~/.openclaw/workspace/llm_guard/plugin

# 3) 全局禁用原始不安全工具
openclaw config set tools.deny '["web_fetch", "browser", "read"]'

# 4) 重启网关
openclaw gateway restart
```

## 安装步骤（详细）

### 1) 安装 Python 服务

```bash
cd ~/.openclaw/workspace/llm_guard
./install.sh
```

脚本会创建 Python 虚拟环境并安装依赖（模型下载体积约 1.5~2GB）。

### 2) 启动服务

方式 A：`systemd`（生产推荐）

```bash
cp llm-guard.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable llm-guard.service
systemctl --user start llm-guard.service
```

方式 B：手动启动

```bash
./start.sh
```

### 3) 安装 OpenClaw 插件

```bash
openclaw plugins install ~/.openclaw/workspace/llm_guard/plugin
```

### 4) 配置工具禁用（关键）

在 `~/.openclaw/openclaw.json` 里加入 `tools.deny`：

```json
{
  "tools": {
    "deny": ["web_fetch", "browser", "read"]
  }
}
```

这一步会强制代理只能使用 `safe_*` 工具，而不能直接调用原始工具。

配置验证：

```bash
# 检查 deny 列表
openclaw config get tools.deny
# 预期: ["web_fetch", "browser", "read"]

# 检查沙箱策略
openclaw sandbox explain
# 预期包含: deny (global): web_fetch, browser, read

# 检查插件是否注册成功
journalctl --user -u clawdbot-gateway.service | grep -i "llm-guard"
# 预期包含: safe_web_fetch, safe_browser, safe_read
```

### 5) 重启网关

```bash
systemctl --user restart clawdbot-gateway.service
# 或
openclaw gateway restart
```

### 6) 验证安装

```bash
# 健康检查
curl -s http://127.0.0.1:8765/health | jq
```

预期返回示例：

```json
{
  "status": "healthy",
  "input_scanner_count": 6,
  "output_scanner_count": 4,
  "timestamp": "2026-02-05T...",
  "uptime_seconds": 123.4,
  "scans_completed": {"input": 0, "output": 0}
}
```

## 工作机制

### safe_web_fetch（BLOCK）

当代理抓取 URL 时：

1. 包装原始 `web_fetch`（不是重写实现）。
2. 去除 OpenClaw 的安全包装层文本。
3. 用 LLM Guard 扫描提取后的正文。
4. 命中威胁：返回 `text: null, blocked: true` 和安全元数据。
5. 未命中：返回原始正文，并标记 `security.scanned: true`。

拦截返回示例：

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

正常返回示例：

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

### safe_read / safe_browser（WARN）

这两个工具检测到风险时不会直接拦截，而是前置警告再返回内容：

```text
[Security Warning: Threats detected - PromptInjection, Secrets]

...original content follows...
```

## 架构

```text
┌─────────────────────────────────────────────────────────────┐
│                    openclaw.json                            │
│  tools.deny: [web_fetch, browser, read]                    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              LLM Guard 插件（Node.js）                      │
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
│              LLM Guard 服务（Python）                       │
│  localhost:8765                                             │
│  ┌─────────────────────────────────────────────────────────┐│
│  │  扫描器：                                                ││
│  │  - PromptInjection（ML，阈值 0.9）                       ││
│  │  - Secrets（密钥脱敏）                                   ││
│  │  - InvisibleText（隐藏 Unicode）                         ││
│  │  - Toxicity（阈值 0.7）                                  ││
│  │  - BanSubstrings（企业敏感词）                            ││
│  │  - Regex（API Key 正则）                                 ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

## 组件说明

### Python 服务（`service/`）
- `scanner_service.py`：FastAPI HTTP 服务（8765）
- `config.py`：扫描器配置（阈值、模式、敏感词）
- `health_check.py`：健康检查工具
- `test.py`：集成测试

### OpenClaw 插件（`plugin/`）
- `index.js`：工具注册入口
- `src/llm-guard-client.js`：Python 服务客户端
- `src/safe-web-fetch.js`：`web_fetch` 的 BLOCK 包装
- `src/safe-browser.js`：`browser` 的 WARN 包装
- `src/safe-read.js`：`read` 的 WARN 包装

## 扫描器配置

编辑 `service/config.py` 可调整策略。

### 提示注入（ML）

```python
PromptInjection(threshold=0.9)  # 越高越保守，误报更少
```

### 密钥检测

```python
Secrets(redact_mode="all")  # 命中后以 ****** 脱敏
```

注意：请使用字符串 `"all"`，不要写成布尔值 `True`。

### API Key 正则

```python
BUSINESS_API_PATTERNS = [
    r"lin_api_[A-Za-z0-9]{32,}",
    r"ya29\.[A-Za-z0-9_-]{100,}",
    r"GROQ_API_KEY=[a-zA-Z0-9_-]{50,}",
]
```

### 企业敏感词

```python
COMPANY_SENSITIVE_TERMS = [
    "internal-project-name",
    "client-company-name",
]
```

## 维护建议
- 定期升级 LLM Guard 依赖与模型。
- 把误报样本加入测试集，按业务调整阈值。
- 对 `safe_web_fetch` 持续保持 BLOCK，避免高风险 URL 直通。
