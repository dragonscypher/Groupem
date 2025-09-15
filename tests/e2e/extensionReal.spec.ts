import { chromium, expect, request, test } from '@playwright/test';
import * as path from 'path';

// This test launches a persistent Chromium context with the packed extension dist
// and interacts with the popup to validate session save functionality end-to-end.
// Assumes extension already built via root build (vite build outputs to dist/).

test('real extension popup auth + save session', async () => {
    // Pre-create user (idempotent: ignore if exists)
    const api = await request.newContext();
    await api.post('http://localhost:8080/auth/register', {
        data: { email: 'ext@test.com', password: 'Passw0rd!', autoTotp: false }
    }).catch(() => { });
    // Build path
    const extPath = path.resolve(__dirname, '..', '..', 'extension', 'dist');

    // Launch Chromium with extension
    const context = await chromium.launchPersistentContext('', {
        headless: false, // need UI for extension
        args: [
            `--disable-extensions-except=${extPath}`,
            `--load-extension=${extPath}`
        ]
    });
    try {
        // Create synthetic tabs using data URLs (cannot rely on external DNS in CI)
        const mk = async (host: string) => {
            const p = await context.newPage();
            await p.goto('https://example.com/?host=' + host);
            return p;
        };
        await mk('alpha');
        await mk('beta');
        await mk('news');

        // Poll chrome.storage.local for extension id persisted by background (management permission)
        let extId: string | null = null;
        const pollStart = Date.now();
        while (!extId && Date.now() - pollStart < 7000) {
            // Open a temporary blank page and attempt to access extension storage via evaluating an extension URL iframe
            // Simpler: attempt to read from each service worker if any; fallback to guess through executing a no-op (not available yet)
            // Instead we just try: open popup.html via each possible service worker (none yet) so trigger activator again
            // Finally rely on content script pings causing background to set storage; we cannot directly read storage from normal page.
            // So as workaround: create a devtools protocol session to list targets (not exposed directly via Playwright API). For now simulate delay.
            await new Promise(r => setTimeout(r, 500));
            // Try to inspect service workers each iteration
            const sw = context.serviceWorkers()[0];
            if (sw) {
                const mu = sw.url();
                const m = mu.match(/chrome-extension:\/\/([a-p]{32})\//);
                if (m) extId = m[1];
            }
        }
        expect(extId, 'extension id not resolved within timeout').toBeTruthy();

        // Open the popup via extension URL
        const popup = await context.newPage();
        await popup.goto(`chrome-extension://${extId}/popup.html`);
        // Login screen first
        await popup.waitForSelector('text=Login');
        await popup.fill('input[placeholder="Email"]', 'ext@test.com');
        await popup.fill('input[placeholder="Password"]', 'Passw0rd!');
        await popup.click('button:has-text("Login")');
        // After login, main UI should appear
        await popup.waitForSelector('text=Save Session');
        // Save a session
        await popup.click('button:has-text("Save Session")');
        // Wait for Saved Sessions list to show an entry
        await popup.waitForSelector('h4:text("Saved Sessions")');
        // small delay for backend round trip
        await popup.waitForTimeout(800);
        const sessionItems = popup.locator('h4:text("Saved Sessions") + ul li');
        expect(await sessionItems.count()).toBeGreaterThanOrEqual(1);
    } finally {
        await context.close();
    }
});
