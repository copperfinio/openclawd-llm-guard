/**
 * Safe Read Tool
 * Wraps file read with LLM Guard protection, excluding trusted paths
 */
import { LLMGuardClient } from './llm-guard-client.js';
import { readFile } from 'fs/promises';
import { resolve } from 'path';

// Trusted path patterns - skip scanning for these (workspace files)
const TRUSTED_PATTERNS = [
    /IDENTITY\.md$/i,
    /SOUL\.md$/i,
    /USER\.md$/i,
    /TOOLS\.md$/i,
    /AGENTS\.md$/i,
    /\.openclaw\/workspace\//,
    /\.openclaw\/memory\//,
];

function isTrustedPath(filePath) {
    const normalized = resolve(filePath);
    return TRUSTED_PATTERNS.some(pattern => pattern.test(normalized));
}

export function createSafeRead({ config, runtime }) {
    const serviceUrl = config?.serviceUrl || 'http://127.0.0.1:8765';
    const timeout = config?.timeout || 5000;
    const fallbackOnError = config?.fallbackOnError !== false;

    const llmGuard = new LLMGuardClient(serviceUrl, timeout);

    return {
        description: "Read file contents with ML-based prompt injection protection. Use instead of read for external/untrusted files.",

        async execute(_id, params) {
            const { path: filePath, offset, limit } = params || {};

            // Step 1: Read the file
            let content;
            try {
                const absolutePath = resolve(filePath);
                content = await readFile(absolutePath, 'utf-8');

                // Apply offset and limit if specified
                if (offset !== undefined || limit !== undefined) {
                    const lines = content.split('\n');
                    const start = offset || 0;
                    const end = limit ? start + limit : lines.length;
                    content = lines.slice(start, end).join('\n');
                }
            } catch (readError) {
                return {
                    content: [{ type: "text", text: `Error: Failed to read file: ${readError.message}` }]
                };
            }

            // Step 2: Check if path is trusted (skip scanning)
            if (isTrustedPath(filePath)) {
                return {
                    content: [{ type: "text", text: content }]
                };
            }

            // Step 3: Check if LLM Guard service is healthy
            const healthy = await llmGuard.isHealthy();

            if (!healthy) {
                if (fallbackOnError) {
                    return {
                        content: [{ type: "text", text: `[Warning: LLM Guard unavailable - content not scanned]\n\n${content}` }]
                    };
                } else {
                    return {
                        content: [{ type: "text", text: "Error: LLM Guard service unavailable and fallback disabled" }]
                    };
                }
            }

            // Step 4: Scan content for threats
            try {
                const scanResult = await llmGuard.scanInput(content, filePath);

                let prefix = '';
                if (!scanResult.is_valid) {
                    prefix = `[Security Warning: Threats detected - ${scanResult.threats_detected.join(', ')}]\n\n`;
                }

                return {
                    content: [{ type: "text", text: `${prefix}${scanResult.sanitized_content}` }]
                };
            } catch (scanError) {
                if (fallbackOnError) {
                    return {
                        content: [{ type: "text", text: `[Warning: LLM Guard scan failed - ${scanError.message}]\n\n${content}` }]
                    };
                } else {
                    return {
                        content: [{ type: "text", text: `Error: LLM Guard scan failed: ${scanError.message}` }]
                    };
                }
            }
        }
    };
}

export default createSafeRead;
