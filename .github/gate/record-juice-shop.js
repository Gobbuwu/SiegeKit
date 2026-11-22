// Records test account A using OWASP Juice Shop in Chromium, as a person
// would before a write-replay scan (ADR 0049 item 10, ADR 0054): every kind
// of change the shop has. Each step must work, or the recording is not the
// known one and the gate fails here rather than in the answer.
//
// Usage: node record-juice-shop.js BASE EMAIL PASSWORD OUT.har
const { chromium } = require('playwright');

const [base, email, password, out] = process.argv.slice(2);

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ recordHar: { path: out, content: 'embed' } });
  await ctx.addInitScript(() => { try { localStorage.setItem('language', 'en'); } catch (e) { /* no storage */ } });
  await ctx.addCookies([
    { name: 'cookieconsent_status', value: 'dismiss', url: base },
    { name: 'welcomebanner_status', value: 'dismiss', url: base },
  ]);
  const p = await ctx.newPage();
  const go = async (h) => { await p.goto(base + h); await p.waitForTimeout(1500); };
  const fill = async (placeholder, v) => p.locator(`input[placeholder="${placeholder}"], textarea[placeholder="${placeholder}"]`).fill(v);
  const address = async (street) => {
    await go('/#/address/create');
    await fill('Please provide a country.', 'X');
    await fill('Please provide a name.', 'Alice');
    await fill('Please provide a mobile number.', '1234567');
    await fill('Please provide a ZIP code.', '12345');
    await fill('Please provide an address.', street);
    await fill('Please provide a city.', 'Town');
    await fill('Please provide a state.', 'S');
    await p.click('#submitButton');
    await p.waitForTimeout(2000);
  };
  const steps = [
    ['log in', async () => {
      await go('/#/login');
      await p.fill('#email', email);
      await p.fill('#password', password);
      await p.click('#loginButton');
      await p.waitForTimeout(2500);
    }],
    ['add 2 products to the basket', async () => {
      await go('/#/search');
      const b = p.locator('button[aria-label="Add to Basket"]');
      await b.nth(0).click(); await p.waitForTimeout(1200);
      await b.nth(1).click(); await p.waitForTimeout(1200);
    }],
    ['add 1 to an item', async () => { await go('/#/basket'); await p.locator('mat-row button').nth(1).click(); await p.waitForTimeout(1500); }],
    ['remove an item', async () => { await p.locator('mat-row button').nth(2).click(); await p.waitForTimeout(1500); }],
    ['add an address', () => address('1 Main St')],
    ['edit the address', async () => {
      await go('/#/address/saved');
      await p.locator('tr button').nth(0).click(); await p.waitForTimeout(1500);
      await p.locator('input[placeholder="Please provide a city."]').fill('Changed');
      await p.click('#submitButton'); await p.waitForTimeout(2000);
    }],
    ['add a card', async () => {
      await go('/#/saved-payment-methods');
      await p.locator('mat-expansion-panel-header').first().click(); await p.waitForTimeout(800);
      const ins = p.locator('mat-expansion-panel input');
      await ins.nth(0).fill('Alice');
      await ins.nth(1).fill('4111111111111111');
      const sel = p.locator('mat-expansion-panel select');
      await sel.nth(0).selectOption('1');
      await sel.nth(1).selectOption('2090');
      await p.click('#submitButton'); await p.waitForTimeout(2000);
    }],
    ['delete the address', async () => { await go('/#/address/saved'); await p.locator('tr button').nth(1).click(); await p.waitForTimeout(1500); }],
    ['write a review', async () => {
      await go('/#/search');
      await p.locator('mat-card').first().click(); await p.waitForTimeout(1500);
      await p.locator('textarea').fill('my review');
      await p.click('#submitButton'); await p.waitForTimeout(1500);
      await p.keyboard.press('Escape');
    }],
    ['edit the review', async () => {
      await go('/#/search');
      await p.locator('mat-card').first().click(); await p.waitForTimeout(1500);
      await p.locator('button[aria-label="Edit Review"]').first().dispatchEvent('click'); await p.waitForTimeout(1200);
      await p.locator('textarea[aria-label="Text field to edit a product review"]').fill('my review, edited');
      await p.locator('button[aria-label="Send the review"]').last().click(); await p.waitForTimeout(1500);
      await p.keyboard.press('Escape'); await p.keyboard.press('Escape');
    }],
    ['send feedback', async () => {
      await go('/#/contact');
      await p.locator('#comment').fill('nice shop');
      // The rating slider takes no typed value on some layouts; the form
      // is sent either way (as measured, 2026-11-21).
      await p.locator('#rating').click().catch(() => {});
      const r = p.locator('mat-slider input');
      if (await r.count()) { await r.first().fill('4').catch(() => {}); }
      const q = await p.locator('#captcha').innerText();
      // The captcha is arithmetic on small whole numbers, such as "3*7+1".
      if (!/^[0-9+\-*\s]+$/.test(q)) throw new Error('unexpected captcha ' + q);
      await p.locator('#captchaControl').fill(String(Function('return (' + q + ')')()));
      await p.click('#submitButton'); await p.waitForTimeout(1500);
    }],
    ['check out', async () => {
      await go('/#/search');
      await p.locator('button[aria-label="Add to Basket"]').nth(2).click(); await p.waitForTimeout(1200);
      await address('2 Main St');
      await go('/#/basket');
      await p.click('#checkoutButton'); await p.waitForTimeout(1500);
      for (let k = 0; k < 3; k++) {
        await p.locator('mat-radio-button').first().click(); await p.waitForTimeout(600);
        await p.locator('button.btn-next:not([disabled]), button[aria-label="Proceed to review"]:not([disabled]), button[aria-label="Proceed to delivery method selection"]:not([disabled])').first().click();
        await p.waitForTimeout(1500);
      }
      await p.locator('button[aria-label="Complete your purchase"]').click(); await p.waitForTimeout(2500);
      if (!p.url().includes('/order-completion/')) throw new Error('no order confirmation: ' + p.url());
    }],
    ['open the account pages', async () => {
      for (const r of ['/#/order-history', '/#/wallet', '/#/address/saved', '/#/saved-payment-methods', '/#/basket']) await go(r);
    }],
    ['log out', async () => {
      await p.click('#navbarAccount'); await p.waitForTimeout(500);
      await p.click('#navbarLogoutButton'); await p.waitForTimeout(2000);
    }],
  ];
  for (const [name, fn] of steps) {
    try {
      await fn();
      console.log('recorded:', name);
    } catch (e) {
      console.error('recording failed at "' + name + '": ' + e.message.split('\n')[0]);
      await browser.close();
      process.exit(1);
    }
  }
  await ctx.close();
  await browser.close();
})();
