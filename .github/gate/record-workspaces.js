// Records test account A on the write-replay gate's Next.js workspace
// pages (issues #95 and #96) in Chromium: A creates a workspace, renames
// it, archives it, sets its topic, adds B as a member, adds a note, sets a
// webhook, reads the notes, sends feedback on the public page and opens
// the list, whose link to /latest the browser prefetches. Every write is
// a Server Action posted to the page's URL. It also logs B and C in and
// writes their cookies as session files. Each step must work, or the gate
// fails here rather than in the answer.
//
// Usage: node record-workspaces.js BASE A-EMAIL B-EMAIL C-EMAIL PASSWORD OUT.har B-SESSION C-SESSION
const { chromium } = require('playwright');
const fs = require('fs');

const [base, emailA, emailB, emailC, password, out, sessionB, sessionC] = process.argv.slice(2);

(async () => {
  const browser = await chromium.launch();
  const login = async (ctx, email) => {
    const p = await ctx.newPage();
    await p.goto(base + '/login');
    await p.fill('#email', email);
    await p.fill('#password', password);
    await Promise.all([p.waitForURL(base + '/'), p.click('button')]);
    return p;
  };
  const fail = async (what, e) => {
    console.error('recording failed at "' + what + '": ' + e.message.split('\n')[0]);
    await browser.close();
    process.exit(1);
  };
  for (const [email, file] of [[emailB, sessionB], [emailC, sessionC]]) {
    try {
      const c = await browser.newContext();
      await login(c, email);
      fs.writeFileSync(file, 'Cookie: ' + (await c.cookies()).map((k) => k.name + '=' + k.value).join('; ') + '\n', { mode: 0o600 });
      await c.close();
    } catch (e) { await fail('log in ' + email, e); }
  }
  const ctx = await browser.newContext({ recordHar: { path: out, content: 'embed' } });
  let p, id;
  const submit = async (form, values, wait) => {
    for (const [k, v] of Object.entries(values)) await p.fill(`#${form} input[name="${k}"]`, v);
    await p.click(`#${form} button`);
    await wait();
    await p.waitForTimeout(700);
  };
  const notice = (n) => () => p.waitForURL((u) => u.searchParams.get('notice') === n);
  const status = (form, text) => () => p.locator(`#${form} [role=status]`, { hasText: text }).waitFor();
  const steps = [
    ['log in', async () => { p = await login(ctx, emailA); }],
    ['create a workspace', async () => {
      await p.goto(base + '/w');
      await submit('create', { name: 'Gate workspace alpha' }, notice('created'));
      id = new URL(p.url()).pathname.split('/')[2];
      if (!/^[0-9a-f-]{36}$/.test(id)) throw new Error('workspace page at ' + p.url());
    }],
    ['rename it', async () => { await p.goto(base + '/w/' + id); await p.waitForTimeout(700); await submit('rename', { name: 'Gate workspace bravo' }, notice('renamed')); }],
    ['archive it', async () => { await submit('archive', {}, status('archive', 'archived')); }],
    ['set its topic', async () => { await submit('topic', { topic: 'quarterly plans' }, status('topic', 'saved')); }],
    ['add B', async () => { await submit('member', { email: emailB }, notice('member-added')); }],
    ['add a note', async () => { await submit('note', { note: 'private note' }, notice('note-added')); }],
    ['set the webhook', async () => { await submit('webhook', { url: 'http://127.0.0.1:9/hook' }, notice('webhook-saved')); }],
    ['read the notes', async () => { await p.goto(base + '/w/' + id + '/notes'); await p.waitForTimeout(700); }],
    ['send feedback', async () => { await p.goto(base + '/p/' + id); await p.waitForTimeout(700); await submit('feedback', {}, notice('thanks')); }],
    ['open the list', async () => {
      await p.goto(base + '/w');
      await p.waitForTimeout(2000); // the browser prefetches /latest and the workspace's page
      await Promise.all([p.waitForURL(base + '/latest'), p.click('a[href="/latest"]')]);
      await p.waitForTimeout(700);
    }],
  ];
  for (const [what, fn] of steps) {
    try { await fn(); } catch (e) { await fail(what, e); }
  }
  await ctx.close();
  await browser.close();
  console.log('recorded workspace ' + id);
})();
