// Records test account A (alice) on Gitea's web UI in Chromium: in her
// private repository, where bob is a collaborator and carol is not, she
// opens an issue, comments on it and renames it (ADR 0051, ADR 0054). It
// also logs bob and carol in and writes their cookies as session files.
// Each step must work, or the gate fails here rather than in the answer.
//
// Usage: node record-gitea.js BASE PASSWORD OUT.har B-SESSION C-SESSION
const { chromium } = require('playwright');
const fs = require('fs');

const [base, password, out, sessionB, sessionC] = process.argv.slice(2);

(async () => {
  const browser = await chromium.launch();
  const login = async (ctx, u) => {
    const p = await ctx.newPage();
    await p.goto(base + '/user/login');
    await p.fill('#user_name', u);
    await p.fill('#password', password);
    await Promise.all([p.waitForNavigation(), p.click('form.ui.form button.primary')]);
    if (p.url().includes('/user/login')) throw new Error(u + ' could not log in');
    return p;
  };
  const fail = async (what, e) => {
    console.error('recording failed at "' + what + '": ' + e.message.split('\n')[0]);
    await browser.close();
    process.exit(1);
  };
  for (const [u, file] of [['bob', sessionB], ['carol', sessionC]]) {
    try {
      const c = await browser.newContext();
      await login(c, u);
      fs.writeFileSync(file, 'Cookie: ' + (await c.cookies()).map((k) => k.name + '=' + k.value).join('; ') + '\n', { mode: 0o600 });
      await c.close();
    } catch (e) { await fail('log in ' + u, e); }
  }
  const ctx = await browser.newContext({ recordHar: { path: out, content: 'embed' } });
  let p;
  const go = async (h) => { await p.goto(base + h); await p.waitForTimeout(700); };
  const steps = [
    ['log in', async () => { p = await login(ctx, 'alice'); }],
    ['open the repository', async () => { await go('/alice/priv'); await go('/alice/priv/issues'); }],
    ['open an issue', async () => {
      await go('/alice/priv/issues/new');
      await p.fill('#issue_title', 'private issue');
      await Promise.all([p.waitForNavigation(), p.click('form#new-issue button.primary')]);
      if (!p.url().endsWith('/alice/priv/issues/2')) throw new Error('new issue at ' + p.url());
    }],
    ['comment', async () => {
      await go('/alice/priv/issues/2');
      await p.fill('#comment-form textarea', 'a private comment');
      await Promise.all([p.waitForNavigation(), p.click('#comment-form button.primary')]);
    }],
    ['rename the issue', async () => {
      await go('/alice/priv/issues/2');
      await p.click('#issue-title-edit-show');
      await p.fill('#issue-title-editor input', 'renamed private');
      await p.click('#issue-title-editor button.primary');
      await p.waitForTimeout(1500);
    }],
    ['open a file and the first issue', async () => { await go('/alice/priv/src/branch/main/README.md'); await go('/alice/priv/issues/1'); }],
  ];
  for (const [name, fn] of steps) {
    try {
      await fn();
      console.log('recorded:', name);
    } catch (e) { await fail(name, e); }
  }
  await ctx.close();
  await browser.close();
})();
