// alice in private repo alice/priv (bob = collaborator): view, new issue, comment, edit title. Writes bob/carol cookies.
const { chromium } = require('playwright');
(async () => {
  const B = 'http://127.0.0.1:3001';
  const browser = await chromium.launch();
  const login = async (ctx, u) => { const p = await ctx.newPage(); await p.goto(B + '/user/login'); await p.fill('#user_name', u); await p.fill('#password', 'Passw0rd!x1');
    await Promise.all([p.waitForNavigation(), p.click('form.ui.form button.primary')]); return p; };
  for (const u of ['bob', 'carol']) { const c = await browser.newContext(); await login(c, u);
    require('fs').writeFileSync(u + '-gt.session', 'Cookie: ' + (await c.cookies()).map(c => c.name + '=' + c.value).join('; ') + '\n'); await c.close(); }
  const ctx = await browser.newContext({ recordHar: { path: process.argv[2], content: 'embed' } });
  const step = async (name, fn) => { try { await fn(); console.log('ok', name); } catch (e) { console.log('FAIL', name, e.message.split('\n')[0]); } };
  let p;
  await step('login', async () => { p = await login(ctx, 'alice'); });
  const go = async (h) => { await p.goto(B + h); await p.waitForTimeout(700); };
  await step('view repo', async () => { await go('/alice/priv'); await go('/alice/priv/issues'); });
  await step('new issue', async () => { await go('/alice/priv/issues/new'); await p.fill('#issue_title', 'private issue');
    await Promise.all([p.waitForNavigation(), p.click('form#new-issue button.primary')]); });
  await step('comment', async () => { await go('/alice/priv/issues/2'); await p.fill('#comment-form textarea', 'a private comment');
    await Promise.all([p.waitForNavigation(), p.click('#comment-form button.primary')]); });
  await step('edit title', async () => { await go('/alice/priv/issues/2'); await p.click('#issue-title-edit-show'); await p.fill('#issue-title-editor input', 'renamed private');
    await p.click('#issue-title-editor button.primary'); await p.waitForTimeout(1500); });
  await step('view file', async () => { await go('/alice/priv/src/branch/main/README.md'); await go('/alice/priv/issues/1'); });
  await ctx.close(); await browser.close();
})();
