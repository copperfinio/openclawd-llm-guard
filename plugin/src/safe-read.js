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

        async execute(toolCallId, params, context) {
            // OpenClaw passes: (toolCallId, params, context, ...)
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
                    success: false,
                    error: `Failed to read file: ${readError.message}`,
                    path: filePath
                };
            }

            // Step 2: Check if path is trusted (skip scanning)
            if (isTrustedPath(filePath)) {
                context?.logger?.debug?.(`Trusted path, skipping scan: ${filePath}`);
                return {
                    success: true,
                    content,
                    path: filePath,
                    security: {
                        scanned: false,
                        trusted_path: true
                    }
                };
            }

            // Step 3: Check if LLM Guard service is healthy
            const healthy = await llmGuard.isHealthy();

            if (!healthy) {
                if (fallbackOnError) {
                    context?.logger?.warn?.(`LLM Guard unavailable, returning unscanned file: ${filePath}`);
                    return {
                        success: true,
                        content,
                        path: filePath,
                        warning: "LLM Guard service unavailable - content not scanned"
                    };
                } else {
                    return {
                        success: false,
                        error: "LLM Guard service unavailable and fallback disabled",
                        path: filePath
                    };
                }
            }

            // Step 4: Scan content for threats
            try {
                const scanResult = await llmGuard.scanInput(content, filePath);

                if (!scanResult.is_valid) {
                    context?.logger?.warn?.(`Threats detected in ${filePath}: ${scanResult.threats_detected.join(', ')}`);
                }

                return {
                    success: true,
                    content: scanResult.sanitized_content,
                    path: filePath,
                    security: {
                        scanned: true,
                        is_valid: scanResult.is_valid,
                        risk_score: scanResult.risk_score,
                        threats_detected: scanResult.threats_detected
                    }
                };
            } catch (scanError) {
                if (fallbackOnError) {
                    context?.logger?.warn?.(`LLM Guard scan failed: ${scanError.message}, returning unscanned file`);
                    return {
                        success: true,
                        content,
                        path: filePath,
                        warning: `LLM Guard scan failed: ${scanError.message}`
                    };
                } else {
                    return {
                        success: false,
                        error: `LLM Guard scan failed: ${scanError.message}`,
                        path: filePath
                    };
                }
            }
        }
    };
}

export default createSafeRead;
