import assert from 'node:assert/strict';

// Run against a local Vite server with synthetic accounts; no live credentials.
assert.ok(process.env.BROWSER_LIBRARY, 'Set BROWSER_LIBRARY to an installed module exporting puppeteer.');
const { puppeteer } = await import(process.env.BROWSER_LIBRARY);
const origin = process.env.UI_TEST_ORIGIN || 'http://127.0.0.1:5179';
const browser = await puppeteer.launch({ executablePath: process.env.CHROME_PATH || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', headless: true });
const failures = [];
const clientKey = token => `fixture-signed-api-key-${token}.${'x'.repeat(220)}.fixture-signature`;
const principal = { id: 'fixture-member', kind: 'operator', status: 'active', display_name: 'Alex Morgan', email: 'alex@example.test' };
const clients = [{ id: 'laptop', label: 'Work laptop', status: 'active' }, { id: 'server', label: 'Home server', status: 'active' }, { id: 'old', label: 'Old machine', status: 'revoked' }];
const pass = { id: 'guest', note: 'Sam', display_name: 'Sam', status: 'active', expires_at: '2026-10-12T18:30:00Z', clients: 1, link: '/join#fixture-pass' };
const stats = { accounts: [], active_accounts: 0, total_accounts: 0, last_24h_tokens: 0, generated_at: '2026-09-04T12:00:00Z', aggregate: { total_api_cost: 0, total_subscription_cost: 0, total_subscription_monthly: 0, overall_roi: 0 } };
const open = async (path = '/?view=mine', mode = 'signed-in') => {
  const page = await browser.newPage();
  await page.emulateTimezone('America/Los_Angeles');
  await page.setViewport({ width: 1365, height: 1000 });
  const errors = [];
  let clientRows = ['empty', 'create'].includes(mode) ? [] : clients.map(client => ({ ...client }));
  let keyUnavailable = mode === 'key-retry';
  let releaseReveal;
  let markRevealRequested;
  const revealRelease = new Promise(resolve => { releaseReveal = resolve; });
  const revealRequested = new Promise(resolve => { markRevealRequested = resolve; });
  const waitForReveal = async () => {
    let timer;
    try {
      await Promise.race([revealRequested, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Client reveal was not requested')), page.getDefaultTimeout()); })]);
    } finally { clearTimeout(timer); }
  };
  page.on('pageerror', e => errors.push(e.message));
  await page.setRequestInterception(true);
  page.on('request', async request => {
    const url = new URL(request.url());
    if (url.origin !== origin) { await request.abort(); return; }
    if (!url.pathname.startsWith('/api/') && !url.pathname.startsWith('/config/claude/')) { await request.continue(); return; }
    let body = {};
    let status = 200;
    if (url.pathname.startsWith('/config/claude/')) {
      if (keyUnavailable) { status = 503; body = { error: 'Try again' }; }
      else body = { access_token: clientKey(url.pathname.split('/').pop()) };
    }
    else if (url.pathname === '/api/auth/me') { body = mode === 'guest' ? { ...principal, kind: 'guest' } : principal; if (mode === 'signed-out') { status = 401; body = { error: 'Sign in required' }; } }
    else if (url.pathname === '/api/auth/join') body = { switch_required: true, current: principal };
    else if (url.pathname === '/api/auth/config') body = { operator_exists: true, legacy_signup: true };
    else if (url.pathname === '/api/me/clients') {
      body = clientRows;
      if (request.method() === 'POST') {
        if (mode === 'create') {
          body = { id: 'new-client', label: JSON.parse(request.postData()).label, status: 'active', setup_token: 'fixture-new-client' };
          clientRows.push(body);
        }
        else { status = 503; body = { error: 'Unable to create client. Try again.' }; }
      }
    }
    else if (url.pathname.endsWith('/reveal')) {
      const id = url.pathname.split('/')[4];
      if (id === 'server' && mode === 'reveal-race') { markRevealRequested(); await revealRelease; }
      body = { setup_token: `fixture-${id}` };
    }
    else if (url.pathname.endsWith('/rotate')) {
      const client = clientRows.find(client => client.id === url.pathname.split('/')[4]);
      client.status = 'active';
      body = { ...client, setup_token: `fixture-replaced-${client.id}` };
    }
    else if (url.pathname.startsWith('/api/me/clients/') && request.method() === 'DELETE') {
      clientRows.find(client => client.id === url.pathname.split('/')[4]).status = 'revoked';
      body = { success: true };
    }
    else if (url.pathname === '/api/me/usage' || url.pathname.endsWith('/usage')) body = { hourly: [] };
    else if (url.pathname === '/api/me/passkeys') body = [];
    else if (url.pathname === '/api/passes') body = [pass];
    else if (url.pathname === '/api/console/principals') body = { principals: [{ ...principal, note: '', billable_tokens: 0, api_equivalent_cost_usd: 0, request_count: 0 }, { ...pass, kind: 'guest', billable_tokens: 0, api_equivalent_cost_usd: 0, request_count: 0 }] };
    else if (url.pathname === '/api/console/members') body = { principal, link: `${origin}/recover#fixture-invite`, expires_at: '2026-09-04T12:30:00Z' };
    else if (url.pathname === '/api/console/audit') body = [];
    else if (url.pathname === '/api/console/analytics-health') body = { health: { state: 'CURRENT', outbox_depth: 0 }, accounting_gaps: [] };
    else if (url.pathname === '/api/pool/stats') body = stats;
    else if (url.pathname === '/api/pool/signal') body = { hourly: [], economics: [], origin_weekly: [] };
    else if (url.pathname === '/api/pool/catalog') body = { models: [] };
    else { status = 503; body = { error: 'Request failed. Try again.' }; }
    await request.respond({ status, contentType: 'application/json', body: JSON.stringify(body) });
  });
  await page.goto(origin + path);
  await page.waitForSelector('h1');
  return { page, errors, releaseReveal, waitForReveal, recoverKey: () => { keyUnavailable = false; } };
};
const clickText = async (page, selector, text) => {
  await page.waitForFunction((selector, text) => [...document.querySelectorAll(selector)].some(el => el.textContent.trim() === text), {}, selector, text);
  await page.evaluate((selector, text) => [...document.querySelectorAll(selector)].find(el => el.textContent.trim() === text).click(), selector, text);
};
const check = async (name, test) => {
  try { await test(); console.log(`PASS ${name}`); }
  catch (error) { failures.push(name); console.error(`FAIL ${name}: ${error.message}`); }
};
try {
  await check('recovery waits for blur and keeps submit enabled', async () => {
    const { page } = await open('/recover#fixture-recovery', 'signed-out');
    await page.type('input[autocomplete="new-password"]', 'a-long-password');
    await page.type('label:nth-child(2) input', 'a');
    assert.equal(await page.$eval('label:nth-child(2) input', el => el.getAttribute('aria-invalid')), 'false');
    assert.equal(await page.$eval('button[type="submit"], .threshold-submit', el => el.disabled), false);
    await page.close();
  });
  await check('Mine reveals a copyable signed API key, URL and model-list curl by default', async () => {
    const { page, errors } = await open('/?view=mine');
    await clickText(page, '.client-card button', 'Show key');
    await page.waitForFunction(() => document.querySelector('.client-api-key')?.textContent.includes('fixture-signed-api-key-fixture-laptop'));
    await page.evaluate(() => Object.defineProperty(navigator.clipboard, 'writeText', { value: async text => { window.fixtureClipboard = text; } }));
    await clickText(page, '.client-api-key button', 'Copy key');
    assert.equal(await page.evaluate(() => window.fixtureClipboard), clientKey('fixture-laptop'));
    await clickText(page, '.client-api-key button', 'Copy URL');
    assert.equal(await page.evaluate(() => window.fixtureClipboard), `${origin}/v1`);
    assert.ok(await page.$eval('.client-api-key pre', el => el.textContent.includes('/v1/models') && el.textContent.includes('Authorization: Bearer fixture-signed-api-key-fixture-laptop')));
    for (const width of [1365, 390]) {
      await page.setViewport({ width, height: 1000 });
      await page.screenshot({ path: `test-results/account-api-key-${width}.png`, fullPage: true });
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    }
    await clickText(page, '.client-platform-tabs button', 'CLI installers');
    assert.ok(await page.$eval('.setup-secret', el => el.textContent.includes('/setup/codex/fixture-laptop')));
    await clickText(page, '.client-card button', 'Hide key');
    assert.equal(await page.$('.setup-secret'), null);
    assert.deepEqual(errors, []);
    await page.close();
  });
  await check('Mine retries key loading, replaces keys, and clears revoked keys', async () => {
    const { page, recoverKey } = await open('/?view=mine', 'key-retry');
    page.on('dialog', dialog => dialog.accept());
    await clickText(page, '.client-card button', 'Show key');
    await page.waitForSelector('.client-api-key [role=alert]');
    recoverKey();
    await clickText(page, '.client-api-key button', 'Retry API key');
    await page.waitForFunction(() => document.querySelector('.client-api-key')?.textContent.includes('fixture-signed-api-key-fixture-laptop'));
    await clickText(page, '.client-card button', 'Replace key');
    await page.waitForFunction(() => document.querySelector('.client-api-key')?.textContent.includes('fixture-signed-api-key-fixture-replaced-laptop'));
    assert.equal(await page.$eval('.mine-clients', el => el.textContent.includes('fixture-signed-api-key-fixture-laptop')), false);
    await clickText(page, '.client-card button', 'Revoke');
    await page.waitForFunction(() => !document.querySelector('.client-api-key'));
    await page.waitForNetworkIdle();
    assert.equal(await page.$eval('.client-card button', el => el.disabled), true);
    await page.close();
  });
  await check('Mine opens new client API keys immediately', async () => {
    const { page } = await open('/?view=mine', 'create');
    await clickText(page, 'button', 'Create first client');
    await page.type('.client-create input', 'Travel laptop');
    await page.click('.client-create .gold-button');
    await page.waitForFunction(() => document.querySelector('.client-api-key')?.textContent.includes('fixture-signed-api-key-fixture-new-client'));
    assert.equal(await page.$eval('.client-header strong', el => el.textContent), 'Travel laptop');
    await page.close();
  });
  await check('setup keeps the latest selection and excludes revoked credentials', async () => {
    const { page, releaseReveal, waitForReveal } = await open('/?view=setup', 'reveal-race');
    await page.waitForFunction(() => document.querySelector('.tool-detail')?.textContent.includes('fixture-laptop'));
    await clickText(page, '.setup-clients button', 'Home server');
    await waitForReveal();
    await clickText(page, '.setup-clients button', 'Work laptop');
    await page.waitForFunction(() => document.querySelector('.tool-detail')?.textContent.includes('fixture-laptop'));
    releaseReveal();
    await page.waitForNetworkIdle();
    assert.equal(await page.$eval('.client-pill.active', el => el.textContent), 'Work laptop');
    assert.ok(await page.$eval('.tool-detail', el => el.textContent.includes('fixture-laptop')));
    const old = await page.$$('.setup-clients button');
    const revoked = [];
    for (const button of old) {
      if (await button.evaluate(el => el.textContent === 'Old machine')) revoked.push(button);
    }
    assert.equal(revoked.length, 1, 'revoked client remains present');
    assert.equal(await revoked[0].evaluate(el => el.disabled), true);
    await page.close();
  });
  await check('clipboard rejection does not report success', async () => {
    const { page } = await open('/?view=setup');
    await page.waitForSelector('.copy-btn');
    await page.evaluate(() => Object.defineProperty(navigator.clipboard, 'writeText', { value: () => Promise.reject(new Error('Denied')) }));
    await page.click('.copy-btn');
    await page.waitForFunction(() => document.querySelector('[role="alert"]')?.textContent.includes('Copy failed'));
    assert.equal(await page.$eval('.copy-btn', el => el.textContent), 'Copy');
    await page.close();
  });
  await check('pass editing preserves local expiry', async () => {
    const { page } = await open('/?view=passes');
    await page.waitForSelector('.pass-row');
    await page.evaluate(() => [...document.querySelectorAll('.pass-row button')].find(el => el.textContent.toLowerCase() === 'edit').click());
    assert.equal(await page.$eval('input[type="datetime-local"]', el => el.value), '2026-10-12T11:30');
    await page.close();
  });
  await check('declining a guest pass keeps the current account', async () => {
    const { page } = await open('/join#fixture-pass');
    await clickText(page, 'button', 'Stay signed in as Alex Morgan');
    await page.waitForSelector('.identity-strip');
    assert.ok(await page.$eval('.identity-strip', el => el.textContent.includes('Alex Morgan')));
    await page.close();
  });
  await check('guests do not see unavailable pool metrics or a no-op refresh', async () => {
    const { page } = await open('/?view=mine', 'guest');
    await page.waitForSelector('.identity-strip');
    assert.equal(await page.$eval('.rail-readouts', el => el.textContent.includes('Refresh')), false);
    assert.equal(await page.$eval('.rail-readouts', el => el.textContent.includes('accounts live')), false);
    await page.close();
  });
  await check('failed client creation preserves input', async () => {
    const { page } = await open('/?view=setup', 'empty');
    await clickText(page, 'button', 'Create a client');
    await page.type('.setup-client-create input', 'Travel laptop');
    await page.click('.setup-client-create .gold-button');
    await page.waitForSelector('[role="alert"]');
    assert.equal(await page.$eval('.setup-client-create input', el => el.value), 'Travel laptop');
    await page.close();
  });
  await check('new clients open their own setup immediately', async () => {
    const { page } = await open('/?view=setup', 'create');
    await clickText(page, 'button', 'Create a client');
    await page.type('.setup-client-create input', 'Travel laptop');
    await page.click('.setup-client-create .gold-button');
    await page.waitForSelector('.tool-detail');
    assert.equal(await page.$eval('.client-pill.active', el => el.textContent), 'Travel laptop');
    assert.ok(await page.$eval('.tool-detail', el => el.textContent.includes('fixture-new-client')));
    await page.close();
  });
  await check('member invitations show the private link and expiry', async () => {
    const { page } = await open('/?view=console');
    await clickText(page, 'button', 'Add member');
    await page.type('.member-admin input[type=email]', 'new@example.test');
    await page.click('.member-admin .gold-button');
    await page.waitForSelector('.member-link-result');
    assert.ok(await page.$eval('.member-link-result', el => el.textContent.includes('30 minutes')));
    assert.ok(await page.$eval('.member-link-result code', el => el.textContent.endsWith('#fixture-invite')));
    await page.close();
  });
  await check('pool account forms preserve credentials on failure', async () => {
    const { page, errors } = await open('/?view=accounts');
    await clickText(page, 'button', 'Add pool account');
    await clickText(page, '.contribution-providers button', 'Kimi');
    await page.type('.contribution-field input', 'fixture-provider-key');
    await page.click('.contribution-dialog .gold-button');
    await page.waitForSelector('.contribution-dialog [role=alert]');
    assert.equal(await page.$eval('.contribution-field input', el => el.value), 'fixture-provider-key');
    for (const width of [1365, 390]) {
      await page.setViewport({ width, height: 1000 });
      await page.screenshot({ path: `test-results/account-provider-${width}.png`, fullPage: true });
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    }
    assert.deepEqual(errors, []);
    await page.close();
  });
  for (const view of ['mine', 'setup', 'passes', 'console']) {
    await check(`${view} renders at desktop and mobile widths`, async () => {
      const { page, errors } = await open(`/?view=${view}`);
      await page.waitForNetworkIdle();
      if (view === 'mine') await clickText(page, 'button', 'Edit profile');
      if (view === 'passes') await clickText(page, 'button', 'Create a pass');
      if (view === 'console') await clickText(page, 'button', 'Add member');
      for (const width of [1365, 390]) {
        await page.setViewport({ width, height: 1000 });
        await page.screenshot({ path: `test-results/account-${view}-${width}.png`, fullPage: true });
        assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `Page overflows at ${width}px`);
      }
      assert.deepEqual(errors, []);
      await page.close();
    });
  }
  await check('sign-in renders and retains input on failure', async () => {
    const { page } = await open('/', 'signed-out');
    await page.type('input[autocomplete="username"]', 'alex@example.test');
    await page.type('input[type="password"]', 'fixture-password');
    await page.click('.threshold-submit');
    await page.waitForSelector('[role="alert"]');
    assert.equal(await page.$eval('input[autocomplete="username"]', el => el.value), 'alex@example.test');
    await page.screenshot({ path: 'test-results/account-signin.png', fullPage: true });
    await page.close();
  });
} finally { await browser.close(); }
if (failures.length) process.exitCode = 1;
