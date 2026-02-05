/**
 * LLM Guard HTTP Client
 * Communicates with the Python scanner service
 */
import fetch from 'node-fetch';

export class LLMGuardClient {
    constructor(serviceUrl = 'http://127.0.0.1:8765', timeout = 5000) {
        this.serviceUrl = serviceUrl;
        this.timeout = timeout;
        this.healthCache = { healthy: null, timestamp: 0 };
        this.healthCacheTTL = 30000; // 30 seconds
    }

    /**
     * Check service health (cached for 30s)
     */
    async isHealthy() {
        const now = Date.now();
        if (this.healthCache.healthy !== null && 
            (now - this.healthCache.timestamp) < this.healthCacheTTL) {
            return this.healthCache.healthy;
        }

        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 2000);

            const response = await fetch(`${this.serviceUrl}/health`, {
                signal: controller.signal
            });
            clearTimeout(timeoutId);

            const healthy = response.ok;
            this.healthCache = { healthy, timestamp: now };
            return healthy;
        } catch (e) {
            this.healthCache = { healthy: false, timestamp: now };
            return false;
        }
    }

    /**
     * Scan input content for threats
     * @param {string} content - Content to scan
     * @param {string|null} source - Source URL or file path
     * @param {string|null} contentType - Content type (e.g., 'text/html') for proper text extraction
     * @returns {Promise<{sanitized_content: string, is_valid: boolean, risk_score: number, threats_detected: string[]}>}
     */
    async scanInput(content, source = null, contentType = null) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);

        try {
            const body = { content, source };
            if (contentType) {
                body.content_type = contentType;
            }

            const response = await fetch(`${this.serviceUrl}/scan/input`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
                signal: controller.signal
            });
            clearTimeout(timeoutId);

            if (!response.ok) {
                throw new Error(`LLM Guard returned ${response.status}`);
            }

            return await response.json();
        } catch (e) {
            clearTimeout(timeoutId);
            throw e;
        }
    }

    /**
     * Scan output content for sensitive data
     * @returns {Promise<{sanitized_content: string, is_valid: boolean, risk_score: number, threats_detected: string[]}>}
     */
    async scanOutput(prompt, output) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);

        try {
            const response = await fetch(`${this.serviceUrl}/scan/output`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ prompt, output }),
                signal: controller.signal
            });
            clearTimeout(timeoutId);

            if (!response.ok) {
                throw new Error(`LLM Guard returned ${response.status}`);
            }

            return await response.json();
        } catch (e) {
            clearTimeout(timeoutId);
            throw e;
        }
    }
}

export default LLMGuardClient;
