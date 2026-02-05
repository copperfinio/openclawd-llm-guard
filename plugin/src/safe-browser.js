/**
 * Safe Browser Tool - Proxy to Original Browser with LLM Guard Protection
 *
 * Proxies all requests to the OpenClaw browser control server (port 18791)
 * and scans text content responses for prompt injection threats.
 *
 * Matches the original browser tool interface exactly.
 */
import { LLMGuardClient } from './llm-guard-client.js';

// Match OpenClaw's jsonResult format from agents/tools/common.js
function jsonResult(payload) {
    return {
        content: [{ type: "text", text: JSON.stringify(payload, null, 2) }],
        details: payload
    };
}

export function createSafeBrowser({ config, runtime }) {
    const serviceUrl = config?.serviceUrl || 'http://127.0.0.1:8765';
    const browserUrl = config?.browserUrl || 'http://127.0.0.1:18791';
    const timeout = config?.timeout || 5000;
    const browserTimeout = config?.browserTimeout || 30000;
    const fallbackOnError = config?.fallbackOnError !== false;

    const llmGuard = new LLMGuardClient(serviceUrl, timeout);

    // Helper to make HTTP requests to the browser control server
    async function browserRequest(method, path, body = null, queryParams = {}) {
        const url = new URL(path, browserUrl);

        for (const [key, value] of Object.entries(queryParams)) {
            if (value !== undefined && value !== null) {
                url.searchParams.set(key, String(value));
            }
        }

        const options = {
            method,
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            signal: AbortSignal.timeout(browserTimeout)
        };

        if (body && method !== 'GET') {
            options.body = JSON.stringify(body);
        }

        const response = await fetch(url.toString(), options);

        if (!response.ok) {
            const text = await response.text();
            throw new Error(`Browser request failed: ${response.status} ${text}`);
        }

        return await response.json();
    }

    // Scan text content with LLM Guard
    async function scanContent(text, source) {
        if (!text || typeof text !== 'string') {
            return { content: text, scanned: false };
        }

        const healthy = await llmGuard.isHealthy();

        if (!healthy) {
            if (fallbackOnError) {
                return {
                    content: `[Warning: LLM Guard unavailable - content not scanned]\n\n${text}`,
                    scanned: false,
                    warning: "LLM Guard service unavailable"
                };
            }

            throw new Error("LLM Guard service unavailable and fallback disabled");
        }

        try {
            const scanResult = await llmGuard.scanInput(text, source);

            let prefix = '';
            if (!scanResult.is_valid) {
                prefix = `[Security Warning: Threats detected - ${scanResult.threats_detected.join(', ')}]\n\n`;
            }

            return {
                content: `${prefix}${scanResult.sanitized_content}`,
                scanned: true,
                is_valid: scanResult.is_valid,
                risk_score: scanResult.risk_score,
                threats_detected: scanResult.threats_detected
            };
        } catch (scanError) {
            if (fallbackOnError) {
                return {
                    content: `[Warning: LLM Guard scan failed - ${scanError.message}]\n\n${text}`,
                    scanned: false,
                    warning: `Scan failed: ${scanError.message}`
                };
            }

            throw scanError;
        }
    }

    // Add security metadata to result
    function addSecurity(result, security) {
        return { ...result, security };
    }

    return {
        description: "Control web browser with ML-based prompt injection protection. Proxies to the original browser tool and scans content for threats.",

        async execute(_id, params) {
            const {
                action,
                target,
                node,
                profile,
                targetUrl,
                targetId,
                // Snapshot params
                limit,
                maxChars,
                mode,
                snapshotFormat,
                refs,
                interactive,
                compact,
                depth,
                selector,
                frame,
                labels,
                // Screenshot params
                fullPage,
                ref,
                element,
                type: imageType,
                // Console params
                level,
                // Upload/dialog params
                paths,
                inputRef,
                timeoutMs,
                accept,
                promptText,
                // Act request (nested object for click, type, etc.)
                request
            } = params || {};

            try {
                // Handle different actions - matching original browser tool interface
                switch (action) {
                    case 'status': {
                        const result = await browserRequest('GET', '/status', null, { profile });
                        return jsonResult(addSecurity(result, { scanned: false, note: "Status check - no content to scan" }));
                    }

                    case 'start': {
                        const result = await browserRequest('POST', '/start', { profile });
                        return jsonResult(addSecurity(result, { scanned: false, note: "Start action - no content to scan" }));
                    }

                    case 'stop': {
                        const result = await browserRequest('POST', '/stop', { profile });
                        return jsonResult(addSecurity(result, { scanned: false, note: "Stop action - no content to scan" }));
                    }

                    case 'profiles': {
                        const result = await browserRequest('GET', '/profiles');
                        return jsonResult(addSecurity(result, { scanned: false, note: "Profiles list - no content to scan" }));
                    }

                    case 'tabs': {
                        const result = await browserRequest('GET', '/tabs', null, { profile });
                        return jsonResult(addSecurity(result, { scanned: false, note: "Tab list - no content to scan" }));
                    }

                    case 'open': {
                        // Open new tab
                        const result = await browserRequest('POST', '/tab/new', {
                            url: targetUrl || 'about:blank'
                        }, { profile });
                        return jsonResult(addSecurity(result, { scanned: false, note: "Tab open - no content to scan" }));
                    }

                    case 'focus': {
                        const result = await browserRequest('POST', '/tab/focus', { targetId }, { profile });
                        return jsonResult(addSecurity(result, { scanned: false, note: "Tab focus - no content to scan" }));
                    }

                    case 'close': {
                        const result = await browserRequest('POST', '/tab/close', { targetId }, { profile });
                        return jsonResult(addSecurity(result, { scanned: false, note: "Tab close - no content to scan" }));
                    }

                    case 'navigate': {
                        if (!targetUrl) {
                            return jsonResult({ error: "targetUrl is required for navigate action", success: false });
                        }

                        const result = await browserRequest('POST', '/navigate', {
                            url: targetUrl,
                            targetId
                        }, { profile });

                        return jsonResult(addSecurity(result, { scanned: false, note: "Navigation action - no content to scan" }));
                    }

                    case 'snapshot': {
                        const queryParams = {
                            targetId,
                            format: snapshotFormat || 'ai',
                            maxChars,
                            mode,
                            labels,
                            interactive,
                            compact,
                            depth,
                            selector,
                            frame,
                            refs,
                            limit,
                            profile
                        };

                        const result = await browserRequest('GET', '/snapshot', null, queryParams);

                        // The snapshot result has the page content in 'snapshot' field (for ai format)
                        // or 'nodes' field (for aria format)
                        let textToScan = null;

                        if (result.format === 'ai' && result.snapshot) {
                            textToScan = result.snapshot;
                        } else if (result.format === 'aria' && result.nodes) {
                            // Convert ARIA nodes to text for scanning
                            textToScan = result.nodes.map(n => `${n.role}: ${n.name || ''} ${n.value || ''}`).join('\n');
                        }

                        if (textToScan) {
                            const scanResult = await scanContent(textToScan, result.url || 'browser snapshot');

                            // Replace the snapshot content with scanned content
                            if (result.format === 'ai') {
                                result.snapshot = scanResult.content;
                            }

                            result.security = {
                                scanned: scanResult.scanned,
                                is_valid: scanResult.is_valid,
                                risk_score: scanResult.risk_score,
                                threats_detected: scanResult.threats_detected,
                                warning: scanResult.warning
                            };
                        } else {
                            result.security = { scanned: false, note: "No text content to scan" };
                        }

                        return jsonResult(result);
                    }

                    case 'screenshot': {
                        const result = await browserRequest('POST', '/screenshot', {
                            targetId,
                            fullPage,
                            ref,
                            element,
                            type: imageType || 'png'
                        }, { profile });

                        // Screenshot is binary - no text to scan
                        return jsonResult(addSecurity(result, { scanned: false, note: "Screenshot action - binary content not scanned" }));
                    }

                    case 'console': {
                        const result = await browserRequest('GET', '/console', null, {
                            targetId,
                            level: level || 'info',
                            profile
                        });

                        // Console messages could contain malicious content
                        if (result.messages && Array.isArray(result.messages)) {
                            const messagesText = result.messages.map(m => m.text || '').join('\n');

                            if (messagesText) {
                                const scanResult = await scanContent(messagesText, 'browser console');
                                result.security = {
                                    scanned: scanResult.scanned,
                                    is_valid: scanResult.is_valid,
                                    risk_score: scanResult.risk_score,
                                    threats_detected: scanResult.threats_detected,
                                    warning: scanResult.warning
                                };
                            } else {
                                result.security = { scanned: false, note: "No console messages" };
                            }
                        } else {
                            result.security = { scanned: false, note: "No console messages" };
                        }

                        return jsonResult(result);
                    }

                    case 'pdf': {
                        const result = await browserRequest('POST', '/pdf', { targetId }, { profile });
                        return jsonResult(addSecurity(result, { scanned: false, note: "PDF action - binary content not scanned" }));
                    }

                    case 'upload': {
                        const result = await browserRequest('POST', '/act', {
                            kind: 'upload',
                            targetId,
                            paths,
                            inputRef
                        }, { profile });
                        return jsonResult(addSecurity(result, { scanned: false, note: "Upload action - no content to scan" }));
                    }

                    case 'dialog': {
                        const result = await browserRequest('POST', '/act', {
                            kind: 'dialog',
                            targetId,
                            accept,
                            promptText
                        }, { profile });
                        return jsonResult(addSecurity(result, { scanned: false, note: "Dialog action - no content to scan" }));
                    }

                    case 'act': {
                        // The "act" action handles all interactions: click, type, press, hover, drag, select, fill, resize, wait, evaluate, close
                        if (!request || typeof request !== 'object') {
                            return jsonResult({ error: "request object is required for act action", success: false });
                        }

                        const result = await browserRequest('POST', '/act', {
                            ...request,
                            targetId: request.targetId || targetId
                        }, { profile });

                        // Evaluate can return arbitrary content - scan it
                        if (request.kind === 'evaluate' && result.value && typeof result.value === 'string') {
                            const scanResult = await scanContent(result.value, 'browser evaluate');
                            result.value = scanResult.content;
                            result.security = {
                                scanned: scanResult.scanned,
                                is_valid: scanResult.is_valid,
                                risk_score: scanResult.risk_score,
                                threats_detected: scanResult.threats_detected,
                                warning: scanResult.warning
                            };
                        } else {
                            result.security = { scanned: false, note: `${request.kind} action - no content to scan` };
                        }

                        return jsonResult(result);
                    }

                    default:
                        return jsonResult({
                            error: `Unknown browser action: ${action}`,
                            success: false,
                            supportedActions: [
                                'status', 'start', 'stop', 'profiles', 'tabs', 'open', 'focus', 'close',
                                'snapshot', 'screenshot', 'navigate', 'console', 'pdf', 'upload', 'dialog', 'act'
                            ]
                        });
                }
            } catch (err) {
                console.error('[safe_browser] Error:', err.message);

                return jsonResult({
                    error: err.message,
                    success: false,
                    action
                });
            }
        }
    };
}

export default createSafeBrowser;
