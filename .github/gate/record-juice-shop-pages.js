// Records the pages an attacker would abuse on OWASP Juice Shop, in
// Chromium, as a person would before a scan with --har (ADR 0055 item 2,
// ADR 0057): sign up a new account, reset its password with the right
// security answer, and log in as the shop's own second-factor user. Each
// step must work, or the recording is not the known one and the gate fails
// here rather than in the answer.
//
// Usage: node record-juice-shop-pages.js BASE EMAIL PASSWORD NEW_PASSWORD OUT.har
//
// The second-factor user is seeded by Juice Shop itself
// (/juice-shop/data/static/users.yml in the image: wurstbrot, with its TOTP
// secret), so the gate needs no 2FA set-up of its own.
const crypto = require('crypto');
const { chromium } = require('playwright');

const [base, email, password, newPassword, out] = process.argv.slice(2);
const answer = 'gate-answer';
const tfaUser = 'wurstbrot@juice-sh.op';
const tfaPassword = 'EinBelegtesBrotMitSchinkenSCHINKEN!';
const tfaSecret = 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH'; // gitleaks:allow (Juice Shop's own public seed value, users.yml)

// RFC 6238 TOTP (SHA-1, 30 s, 6 digits) from a base32 secret (RFC 4648).
function totp(secret, now) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of secret) bits += alphabet.indexOf(c).toString(2).padStart(5, '0');
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(now / 30000)));
  const h = crypto.createHmac('sha1', key).update(counter).digest();
  const o = h[h.length - 1] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, '0');
}

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
  // Waits for the app's answer to a POST and requires the status.
  const posted = async (path, want, click) => {
    const [res] = await Promise.all([
      p.waitForResponse((r) => r.request().method() === 'POST' && new URL(r.url()).pathname === path),
      click(),
    ]);
    if (res.status() !== want) throw new Error(`${path} answered ${res.status()}, want ${want}`);
    await p.waitForTimeout(1000);
  };
  const steps = [
    ['sign up', async () => {
      await go('/#/register');
      await p.fill('#emailControl', email);
      await p.fill('#passwordControl', password);
      await p.fill('#repeatPasswordControl', password);
      await p.click('#securityQuestionControl'); await p.waitForTimeout(500);
      await p.locator('mat-option').first().click();
      await p.fill('#securityAnswerControl', answer);
      await posted('/api/Users/', 201, () => p.click('#registerButton'));
    }],
    ['reset the password', async () => {
      await go('/#/forgot-password');
      await p.fill('#email', email);
      await p.locator('#email').blur(); await p.waitForTimeout(1500);
      await p.fill('#securityAnswer', answer);
      await p.fill('#newPassword', newPassword);
      await p.fill('#newPasswordRepeat', newPassword);
      await posted('/rest/user/reset-password', 200, () => p.click('#resetButton'));
    }],
    ['log in with a second factor', async () => {
      await go('/#/login');
      await p.fill('#email', tfaUser);
      await p.fill('#password', tfaPassword);
      await p.click('#loginButton');
      await p.locator('#totpToken').waitFor();
      // A code made in a window's last seconds can be stale on arrival.
      const left = 30000 - (Date.now() % 30000);
      if (left < 5000) await p.waitForTimeout(left + 500);
      await p.fill('#totpToken', totp(tfaSecret, Date.now()));
      await posted('/rest/2fa/verify', 200, () => p.click('#totpSubmitButton'));
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
