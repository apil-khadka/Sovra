import { defineConfig } from '@playwright/test'

// Real-browser evidence for SOV-041 (continuation guide step 3):
// Chromium drives the packaged origin (app-a) through DOM/JS login,
// holder consent, and verification. Keycloak keeps its own hostname;
// --host-resolver-rules maps it to loopback so no /etc/hosts edit is
// needed. Requires the compose stack up
// (`docker compose up --build -d`); global setup fails fast
// otherwise. No live AI calls; all data is synthetic and disposable.
export default defineConfig({
  testDir: './e2e',
  globalSetup: './e2e/global.setup.ts',
  timeout: 90_000,
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: process.env.SOVRA_BROWSER_BASE ?? 'http://localhost:8080',
    browserName: 'chromium',
    launchOptions: {
      args: ['--host-resolver-rules=MAP sovra-keycloak 127.0.0.1'],
    },
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
})
