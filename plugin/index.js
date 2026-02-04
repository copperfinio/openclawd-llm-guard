/**
 * LLM Guard Security Plugin for OpenClaw
 * Registers safe_* tools with prompt injection protection
 */
import { Type } from '@sinclair/typebox';
import { createSafeWebFetch } from './src/safe-web-fetch.js';
import { createSafeBrowser } from './src/safe-browser.js';
import { createSafeRead } from './src/safe-read.js';

export default {
    id: "llm-guard-security",
    name: "LLM Guard Security",
    description: "ML-based prompt injection protection using LLM Guard",

    async register(api) {
        const config = api.pluginConfig || {};

        if (config.enabled === false) {
            api.logger.info("LLM Guard plugin disabled by configuration");
            return;
        }

        api.logger.info("Registering LLM Guard protected tools with safe_* names...");

        // Register safe_web_fetch tool
        const safeWebFetch = createSafeWebFetch({ config, runtime: api.runtime });
        api.registerTool({
            name: "safe_web_fetch",
            description: safeWebFetch.description,
            parameters: Type.Object({
                url: Type.String({ description: "HTTP or HTTPS URL to fetch" }),
                extractMode: Type.Optional(Type.Union([
                    Type.Literal("markdown"),
                    Type.Literal("text")
                ])),
                maxChars: Type.Optional(Type.Number())
            }),
            execute: safeWebFetch.execute,
            optional: false
        });

        // Register safe_browser tool
        const safeBrowser = createSafeBrowser({ config, runtime: api.runtime });
        api.registerTool({
            name: "safe_browser",
            description: safeBrowser.description,
            parameters: Type.Object({
                action: Type.Union([
                    Type.Literal("navigate"),
                    Type.Literal("screenshot"),
                    Type.Literal("snapshot"),
                    Type.Literal("act"),
                    Type.Literal("click"),
                    Type.Literal("type"),
                    Type.Literal("scroll")
                ]),
                targetUrl: Type.Optional(Type.String()),
                selector: Type.Optional(Type.String()),
                text: Type.Optional(Type.String()),
                waitFor: Type.Optional(Type.String()),
                timeout: Type.Optional(Type.Number())
            }),
            execute: safeBrowser.execute,
            optional: false
        });

        // Register safe_read tool
        const safeRead = createSafeRead({ config, runtime: api.runtime });
        api.registerTool({
            name: "safe_read",
            description: safeRead.description,
            parameters: Type.Object({
                path: Type.String({ description: "Path to the file to read" }),
                offset: Type.Optional(Type.Number()),
                limit: Type.Optional(Type.Number())
            }),
            execute: safeRead.execute,
            optional: false
        });

        api.logger.info("✅ LLM Guard security tools registered: safe_web_fetch, safe_browser, safe_read");
        api.logger.info("⚠️  Ensure openclaw.json has deny list for: web_fetch, browser, read");
    }
};
