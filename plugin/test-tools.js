/**
 * Test script for LLM Guard plugin tools
 * Run with: node test-tools.js
 */
import { createSafeWebFetch } from './src/safe-web-fetch.js';
import { createSafeBrowser } from './src/safe-browser.js';
import { createSafeRead } from './src/safe-read.js';

const config = {
    serviceUrl: 'http://127.0.0.1:8765',
    browserUrl: 'http://127.0.0.1:18791',
    timeout: 5000,
    browserTimeout: 30000,
    fallbackOnError: true
};

async function testLLMGuardHealth() {
    console.log('\n=== Testing LLM Guard Health ===');
    try {
        const response = await fetch('http://127.0.0.1:8765/health');
        const data = await response.json();
        console.log('LLM Guard status:', JSON.stringify(data, null, 2));
        return data.status === 'healthy';
    } catch (err) {
        console.error('LLM Guard not available:', err.message);
        return false;
    }
}

async function testSafeWebFetch() {
    console.log('\n=== Testing safe_web_fetch ===');
    const tool = createSafeWebFetch({ config });

    // Test with a simple URL
    const result = await tool.execute('test-1', {
        url: 'https://example.com',
        maxChars: 5000
    });

    console.log('Result type:', typeof result);
    console.log('Result keys:', Object.keys(result));
    console.log('Content type:', result.content?.[0]?.type);

    // Parse the JSON from the text content
    if (result.content?.[0]?.text) {
        try {
            const parsed = JSON.parse(result.content[0].text);
            console.log('Parsed result keys:', Object.keys(parsed));
            console.log('Security info:', parsed.security);
            console.log('Status:', parsed.status);
            console.log('Text length:', parsed.text?.length);
            console.log('First 200 chars:', parsed.text?.substring(0, 200));
        } catch (e) {
            console.log('Raw text (first 500 chars):', result.content[0].text.substring(0, 500));
        }
    }

    return result;
}

async function testSafeRead() {
    console.log('\n=== Testing safe_read ===');
    const tool = createSafeRead({ config });

    // Test reading a simple file
    const result = await tool.execute('test-2', {
        path: '/etc/hostname'
    });

    console.log('Result type:', typeof result);
    console.log('Result keys:', Object.keys(result));
    console.log('Content type:', result.content?.[0]?.type);
    console.log('Content text (first 200 chars):', result.content?.[0]?.text?.substring(0, 200));

    return result;
}

async function testSafeBrowser() {
    console.log('\n=== Testing safe_browser ===');
    const tool = createSafeBrowser({ config });

    // Test status action (will fail if browser not running, but shows format)
    console.log('\n--- Testing action=status ---');
    const statusResult = await tool.execute('test-3', {
        action: 'status'
    });

    console.log('Result type:', typeof statusResult);
    console.log('Result keys:', Object.keys(statusResult));

    if (statusResult.content?.[0]?.text) {
        try {
            const parsed = JSON.parse(statusResult.content[0].text);
            console.log('Parsed result keys:', Object.keys(parsed));
            if (parsed.error) {
                console.log('Error (expected if browser not running):', parsed.error);
            } else {
                console.log('Status:', parsed);
            }
        } catch (e) {
            console.log('Raw text:', statusResult.content[0].text.substring(0, 500));
        }
    }

    return statusResult;
}

async function compareFormats() {
    console.log('\n=== Comparing Output Formats ===');

    // Direct fetch vs safe_web_fetch
    console.log('\n--- Direct fetch to example.com ---');
    try {
        const directResponse = await fetch('https://example.com');
        const directText = await directResponse.text();
        console.log('Direct fetch status:', directResponse.status);
        console.log('Direct fetch length:', directText.length);
    } catch (e) {
        console.log('Direct fetch error:', e.message);
    }

    console.log('\n--- safe_web_fetch to example.com ---');
    const tool = createSafeWebFetch({ config });
    const safeResult = await tool.execute('compare-1', {
        url: 'https://example.com',
        maxChars: 10000
    });

    if (safeResult.content?.[0]?.text) {
        const parsed = JSON.parse(safeResult.content[0].text);
        console.log('safe_web_fetch result fields:', Object.keys(parsed));
        console.log('safe_web_fetch security:', parsed.security);
    }
}

async function main() {
    console.log('Starting LLM Guard Plugin Tests\n');
    console.log('================================');

    const llmGuardHealthy = await testLLMGuardHealth();

    if (!llmGuardHealthy) {
        console.log('\nWARNING: LLM Guard service not healthy. Tests will use fallback mode.');
    }

    await testSafeWebFetch();
    await testSafeRead();
    await testSafeBrowser();
    await compareFormats();

    console.log('\n================================');
    console.log('Tests complete!');
}

main().catch(console.error);
