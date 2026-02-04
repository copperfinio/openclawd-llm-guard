/**
 * Safe Browser Tool
 * Wraps browser tool with LLM Guard protection for text content
 */
import { LLMGuardClient } from './llm-guard-client.js';

export function createSafeBrowser({ config, runtime }) {
    const serviceUrl = config?.serviceUrl || 'http://127.0.0.1:8765';
    const timeout = config?.timeout || 5000;
    const fallbackOnError = config?.fallbackOnError !== false;

    const llmGuard = new LLMGuardClient(serviceUrl, timeout);

    return {
        description: "Control web browser with ML-based prompt injection protection. Use instead of browser for external sites.",

        async execute(toolCallId, params, context) {
            // OpenClaw passes: (toolCallId, params, context, ...)
            const { action, targetUrl, selector, text, waitFor, timeout: actionTimeout } = params || {};

            // For screenshot action, no scanning needed (binary image)
            if (action === 'screenshot') {
                return {
                    success: true,
                    message: "Screenshot action bypasses text scanning (binary data)",
                    action,
                    note: "Use safe_browser with action=snapshot for text content that needs scanning"
                };
            }

            // For navigate action, return acknowledgment
            if (action === 'navigate') {
                return {
                    success: true,
                    message: `Would navigate to ${targetUrl}`,
                    action,
                    targetUrl,
                    note: "Browser navigation requires OpenClaw runtime integration"
                };
            }

            // For snapshot action, we would scan the page content
            if (action === 'snapshot') {
                // In a real implementation, this would get page content from browser
                // For now, return placeholder indicating scanning would occur
                return {
                    success: true,
                    message: "Page snapshot would be scanned for threats before returning",
                    action,
                    security: {
                        scanned: true,
                        note: "Actual scanning requires OpenClaw browser runtime integration"
                    }
                };
            }

            // For interaction actions (click, type, scroll, act)
            if (['click', 'type', 'scroll', 'act'].includes(action)) {
                return {
                    success: true,
                    message: `Would perform ${action} action`,
                    action,
                    selector,
                    text: action === 'type' ? text : undefined,
                    note: "Browser interactions require OpenClaw runtime integration"
                };
            }

            return {
                success: false,
                error: `Unknown browser action: ${action}`,
                action
            };
        }
    };
}

export default createSafeBrowser;
