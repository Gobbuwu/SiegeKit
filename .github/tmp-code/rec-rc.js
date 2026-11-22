// alice: login, private group secret-ab (with bob): send + edit; DM with bob: send + edit.
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ recordHar: { path: process.argv[2], content: 'embed' } });
  const page = await ctx.newPage();
  await page.goto('http://localhost:3000/home');
  await page.fill('input[name="usernameOrEmail"]', 'alice');
  await page.fill('input[name="password"]', 'Pass-alice-12345');
  await page.click('button[type="submit"]');
  await page.waitForURL(/home/, { timeout: 60000 });
  await page.waitForTimeout(4000);
  for (const room of ['/group/secret-ab', '/direct/bob']) {
    await page.goto('http://localhost:3000' + room);
    const box = page.locator('textarea[name="msg"]');
    await box.waitFor({ timeout: 60000 });
    await page.waitForTimeout(2000);
    await box.fill('private from alice ' + Date.now());
    await box.press('Enter');
    await page.waitForTimeout(3000);
    await box.press('ArrowUp');
    await page.waitForTimeout(1000);
    await box.fill('private edited by alice');
    await box.press('Enter');
    await page.waitForTimeout(3000);
  }
  await ctx.close(); await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
