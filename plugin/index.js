/**
 * LLM Guard Security Plugin for OpenClaw
 * Registers safe_* tools with prompt injection protection
 */
import { Type } from '@sinclair/typebox';
import { createSafeWebFetch } from './src/safe-web-fetch.js';
import { createSafeBrowser } from './src/safe-browser.js';
import { createSafeRead } from './src/safe-read.js';

// Helper to create optional string enum (matches OpenClaw's optionalStringEnum)
function optionalStringEnum(values) {
    return Type.Optional(Type.Union(values.map(v => Type.Literal(v))));
}

// Helper to create required string enum (matches OpenClaw's stringEnum)
function stringEnum(values) {
    return Type.Union(values.map(v => Type.Literal(v)));
}

export default {
    id: "llm-guard-security",
    name: "LLM Guard Security",
    description: "ML-based prompt injection protection using LLM Guard",

    register(api) {
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

        // Browser act kinds for the nested request object
        const BROWSER_ACT_KINDS = [
            "click", "type", "press", "hover", "drag", "select", "fill", "resize", "wait", "evaluate", "close"
        ];

        // Browser tool actions (matching original exactly)
        const BROWSER_TOOL_ACTIONS = [
            "status", "start", "stop", "profiles", "tabs", "open", "focus", "close",
            "snapshot", "screenshot", "navigate", "console", "pdf", "upload", "dialog", "act"
        ];

        // Browser act schema (nested request object for interactions)
        const BrowserActSchema = Type.Object({
            kind: stringEnum(BROWSER_ACT_KINDS),
            // Common fields
            targetId: Type.Optional(Type.String()),
            ref: Type.Optional(Type.String()),
            // click
            doubleClick: Type.Optional(Type.Boolean()),
            button: Type.Optional(Type.String()),
            modifiers: Type.Optional(Type.Array(Type.String())),
            // type
            text: Type.Optional(Type.String()),
            submit: Type.Optional(Type.Boolean()),
            slowly: Type.Optional(Type.Boolean()),
            // press
            key: Type.Optional(Type.String()),
            // drag
            startRef: Type.Optional(Type.String()),
            endRef: Type.Optional(Type.String()),
            // select
            values: Type.Optional(Type.Array(Type.String())),
            // fill
            fields: Type.Optional(Type.Array(Type.Object({}, { additionalProperties: true }))),
            // resize
            width: Type.Optional(Type.Number()),
            height: Type.Optional(Type.Number()),
            // wait
            timeMs: Type.Optional(Type.Number()),
            textGone: Type.Optional(Type.String()),
            // evaluate
            fn: Type.Optional(Type.String())
        });

        // Register safe_browser tool with schema matching original exactly
        const safeBrowser = createSafeBrowser({ config, runtime: api.runtime });
        api.registerTool({
            name: "safe_browser",
            description: safeBrowser.description,
            parameters: Type.Object({
                // Action (required)
                action: stringEnum(BROWSER_TOOL_ACTIONS),
                // Target options
                target: optionalStringEnum(["sandbox", "host", "node"]),
                node: Type.Optional(Type.String()),
                profile: Type.Optional(Type.String()),
                // Navigation
                targetUrl: Type.Optional(Type.String()),
                targetId: Type.Optional(Type.String()),
                // Snapshot params
                limit: Type.Optional(Type.Number()),
                maxChars: Type.Optional(Type.Number()),
                mode: optionalStringEnum(["efficient"]),
                snapshotFormat: optionalStringEnum(["aria", "ai"]),
                refs: optionalStringEnum(["role", "aria"]),
                interactive: Type.Optional(Type.Boolean()),
                compact: Type.Optional(Type.Boolean()),
                depth: Type.Optional(Type.Number()),
                selector: Type.Optional(Type.String()),
                frame: Type.Optional(Type.String()),
                labels: Type.Optional(Type.Boolean()),
                // Screenshot params
                fullPage: Type.Optional(Type.Boolean()),
                ref: Type.Optional(Type.String()),
                element: Type.Optional(Type.String()),
                type: optionalStringEnum(["png", "jpeg"]),
                // Console params
                level: Type.Optional(Type.String()),
                // Upload/dialog params
                paths: Type.Optional(Type.Array(Type.String())),
                inputRef: Type.Optional(Type.String()),
                timeoutMs: Type.Optional(Type.Number()),
                accept: Type.Optional(Type.Boolean()),
                promptText: Type.Optional(Type.String()),
                // Act request (nested object for click, type, press, etc.)
                request: Type.Optional(BrowserActSchema)
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

        api.logger.info("LLM Guard security tools registered: safe_web_fetch, safe_browser, safe_read");
        api.logger.info("Ensure openclaw.json has deny list for: web_fetch, browser, read");
    }
};
