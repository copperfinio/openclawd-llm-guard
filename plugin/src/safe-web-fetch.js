/**
 * Safe Web Fetch Tool
 * WRAPS the original web_fetch tool and scans its output with LLM Guard
 */
import { LLMGuardClient } from './llm-guard-client.js';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

let originalToolFactory = null;

// Strip OpenClaw's security wrapper to get raw content for scanning
// The wrapper looks like:
// SECURITY NOTICE: ...
// <<<EXTERNAL_UNTRUSTED_CONTENT>>>
// Source: Web Fetch
// ---
// [actual content]
// <<<END_EXTERNAL_UNTRUSTED_CONTENT>>>
function stripSecurityWrapper(text) {
    if (!text) return text;

    // Remove SECURITY NOTICE block
    let cleaned = text.replace(/^SECURITY NOTICE:[\s\S]*?\n\n/m, '');

    // Remove wrapper markers
    cleaned = cleaned.replace(/<<<EXTERNAL_UNTRUSTED_CONTENT>>>\nSource:[^\n]*\n---\n?/g, '');
    cleaned = cleaned.replace(/<<<END_EXTERNAL_UNTRUSTED_CONTENT>>>/g, '');

    return cleaned.trim();
}

async function getOriginalTool(config) {
    if (!originalToolFactory) {
        // Try different paths to find openclaw
        const paths = [
            // When running as plugin inside openclaw
            'openclaw/dist/agents/tools/web-fetch.js',
            // Symlinked in node_modules
            join(dirname(fileURLToPath(import.meta.url)), '..', 'node_modules', 'openclaw', 'dist', 'agents', 'tools', 'web-fetch.js'),
            // Global install (Linux)
            '/home/inestyne/.nvm/versions/node/v22.22.0/lib/node_modules/openclaw/dist/agents/tools/web-fetch.js',
        ];

        for (const path of paths) {
            try {
                const mod = await import(path);
                originalToolFactory = mod.createWebFetchTool;
                break;
            } catch {
                continue;
            }
        }

        if (!originalToolFactory) {
            throw new Error('Could not find openclaw web_fetch tool');
        }
    }
    return originalToolFactory({ config });
}

export function createSafeWebFetch({ config, runtime }) {
    const serviceUrl = config?.serviceUrl || 'http://127.0.0.1:8765';
    const timeout = config?.timeout || 5000;
    const fallbackOnError = config?.fallbackOnError !== false;

    const llmGuard = new LLMGuardClient(serviceUrl, timeout);

    return {
        description: "Fetch web content with ML-based prompt injection protection. Wraps web_fetch and scans output.",

        async execute(_id, params) {
            // Step 1: Get and call the ORIGINAL web_fetch tool
            const originalTool = await getOriginalTool(config?.openclawConfig);
            const originalResult = await originalTool.execute(_id, params);

            // Parse the result
            let parsed;
            try {
                parsed = JSON.parse(originalResult.content[0].text);
            } catch {
                return originalResult;
            }

            // If original failed, return as-is
            if (parsed.error || !parsed.text) {
                return originalResult;
            }

            // Step 2: Check LLM Guard health
            const healthy = await llmGuard.isHealthy();

            if (!healthy) {
                if (fallbackOnError) {
                    parsed.security = { scanned: false, warning: "LLM Guard unavailable" };
                    return { content: [{ type: "text", text: JSON.stringify(parsed, null, 2) }], details: parsed };
                }
                parsed.error = "LLM Guard unavailable";
                parsed.text = null;
                return { content: [{ type: "text", text: JSON.stringify(parsed, null, 2) }] };
            }

            // Step 3: Scan the extracted text (strip OpenClaw's security wrapper first)
            const textToScan = stripSecurityWrapper(parsed.text);

            try {
                const scanResult = await llmGuard.scanInput(textToScan, parsed.url);

                if (!scanResult.is_valid) {
                    // BLOCK - threats detected
                    return { content: [{ type: "text", text: JSON.stringify({
                        ...parsed,
                        text: null,
                        blocked: true,
                        error: "Content blocked: prompt injection detected",
                        security: { scanned: true, blocked: true, is_valid: false,
                            risk_score: scanResult.risk_score, threats_detected: scanResult.threats_detected }
                    }, null, 2) }] };
                }

                // PASS - content is safe
                parsed.blocked = false;
                parsed.security = { scanned: true, blocked: false, is_valid: true,
                    risk_score: scanResult.risk_score, threats_detected: [] };
                return { content: [{ type: "text", text: JSON.stringify(parsed, null, 2) }], details: parsed };

            } catch (scanError) {
                if (fallbackOnError) {
                    parsed.security = { scanned: false, warning: scanError.message };
                    return { content: [{ type: "text", text: JSON.stringify(parsed, null, 2) }], details: parsed };
                }
                parsed.error = scanError.message;
                parsed.text = null;
                return { content: [{ type: "text", text: JSON.stringify(parsed, null, 2) }] };
            }
        }
    };
}

export default createSafeWebFetch;
