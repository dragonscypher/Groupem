import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
    testDir: './tests/e2e',
    timeout: 60000,
    retries: 1,
    fullyParallel: true,
    reporter: [['list']],
    globalSetup: './tests/e2e/global-setup.ts',
    use: { headless: true, trace: 'on-first-retry' },
    projects: [
        { name: 'Chromium', use: { ...devices['Desktop Chrome'] } },
        { name: 'Firefox', use: { ...devices['Desktop Firefox'] } },
        {
            name: 'Extension-Chromium',
            testMatch: /extensionReal\.spec\.ts$/,
            use: {
                ...devices['Desktop Chrome'],
                headless: false,
                // We'll launch a persistent context manually inside the test; standard context fine here.
                launchOptions: { args: [] }
            }
        }
    ]
});
