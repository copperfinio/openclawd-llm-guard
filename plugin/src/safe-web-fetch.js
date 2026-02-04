/**
 * Safe Web Fetch Tool
 * Wraps original web_fetch with LLM Guard protection
 */
import { LLMGuardClient } from './llm-guard-client.js';

export function createSafeWebFetch({ config, runtime }) {
    const serviceUrl = config?.serviceUrl || 'http://127.0.0.1:8765';
    const timeout = config?.timeout || 5000;
    const fallbackOnError = config?.fallbackOnError !== false;

    const llmGuard = new LLMGuardClient(serviceUrl, timeout);

    return {
        description: "Fetch web content with ML-based prompt injection protection. Use instead of web_fetch for external URLs.",

        async execute(params, context) {
            const { url, extractMode = 'markdown', maxChars } = params;

            // Step 1: Fetch content using runtime's built-in fetch or http client
            let content;
            try {
                const response = await fetch(url, {
                    headers: {
                        'User-Agent': 'Mozilla/5.0 (compatible; OpenClaw/1.0)',
                        'Accept': 'text/html,application/xhtml+xml,text/plain',
                    }
                });
                
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                
                content = await response.text();
                
                if (maxChars && content.length > maxChars) {
                    content = content.substring(0, maxChars);
                }
            } catch (fetchError) {
                return {
                    success: false,
                    error: `Failed to fetch URL: ${fetchError.message}`,
                    url
                };
            }

            // Step 2: Check if LLM Guard service is healthy
            const healthy = await llmGuard.isHealthy();
            
            if (!healthy) {
                if (fallbackOnError) {
                    context?.logger?.warn?.(`LLM Guard unavailable, returning unscanned content from ${url}`);
                    return {
                        success: true,
                        content,
                        url,
                        warning: "LLM Guard service unavailable - content not scanned"
                    };
                } else {
                    return {
                        success: false,
                        error: "LLM Guard service unavailable and fallback disabled",
                        url
                    };
                }
            }

            // Step 3: Scan content for threats
            try {
                const scanResult = await llmGuard.scanInput(content, url);

                if (!scanResult.is_valid) {
                    context?.logger?.warn?.(`Threats detected in ${url}: ${scanResult.threats_detected.join(', ')}`);
                }

                return {
                    success: true,
                    content: scanResult.sanitized_content,
                    url,
                    security: {
                        scanned: true,
                        is_valid: scanResult.is_valid,
                        risk_score: scanResult.risk_score,
                        threats_detected: scanResult.threats_detected
                    }
                };
            } catch (scanError) {
                if (fallbackOnError) {
                    context?.logger?.warn?.(`LLM Guard scan failed: ${scanError.message}, returning unscanned content`);
                    return {
                        success: true,
                        content,
                        url,
                        warning: `LLM Guard scan failed: ${scanError.message}`
                    };
                } else {
                    return {
                        success: false,
                        error: `LLM Guard scan failed: ${scanError.message}`,
                        url
                    };
                }
            }
        }
    };
}

export default createSafeWebFetch;
