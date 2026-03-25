# OpenClaw 的 LLM Guard 安全插件（指南）

本指南是项目的中文安装与运维说明，目标是让你在 OpenClaw 中快速启用提示注入防护。

## 一、能力说明

插件提供 3 个安全工具，对外部内容先扫描再返回：

| 原始工具 | 安全工具 | 模式 | 行为 |
|---|---|---|---|
| `web_fetch` | `safe_web_fetch` | BLOCK | 命中威胁则拦截并返回空正文 |
| `browser` | `safe_browser` | WARN | 命中威胁则加警告后返回 |
| `read` | `safe_read` | WARN | 命中威胁则加警告后返回 |

## 二、快速部署

```bash
cd ~/.openclaw/workspace/llm_guard
./install.sh
systemctl --user enable --now llm-guard.service
openclaw plugins install ~/.openclaw/workspace/llm_guard/plugin
openclaw config set tools.deny '["web_fetch", "browser", "read"]'
openclaw gateway restart
```

## 三、详细部署

### 1) 安装 Python 扫描服务

```bash
cd ~/.openclaw/workspace/llm_guard
./install.sh
```

### 2) 启动服务

推荐（systemd）：

```bash
cp llm-guard.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable llm-guard.service
systemctl --user start llm-guard.service
```

手动启动：

```bash
./start.sh
```

### 3) 安装插件

```bash
openclaw plugins install ~/.openclaw/workspace/llm_guard/plugin
```

### 4) 禁用不安全原始工具（必须）

将以下配置写入 `~/.openclaw/openclaw.json`：

```json
{
  "tools": {
    "deny": ["web_fetch", "browser", "read"]
  }
}
```

### 5) 重启网关

```bash
systemctl --user restart clawdbot-gateway.service
# 或
openclaw gateway restart
```

## 四、验证

```bash
openclaw config get tools.deny
openclaw sandbox explain
journalctl --user -u clawdbot-gateway.service | grep -i "llm-guard"
curl -s http://127.0.0.1:8765/health | jq
```

健康检查返回 `status: healthy` 即表示服务可用。

## 五、配置建议

编辑 `service/config.py`：
- `PromptInjection(threshold=0.9)`：注入检测阈值
- `Secrets(redact_mode="all")`：密钥脱敏策略
- `BUSINESS_API_PATTERNS`：业务 API Key 模式
- `COMPANY_SENSITIVE_TERMS`：企业敏感词

## 六、运维建议
- 对外网抓取工具持续保持 deny 原始工具策略。
- 误报样本集中回归测试，按业务域调阈值。
- 定期升级模型与依赖，并复测性能和误报率。
