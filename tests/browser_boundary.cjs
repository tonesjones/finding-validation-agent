'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const {policy, broker, createLocalBoundary} = require('../fva/node/browser_boundary.cjs');
const control = 'FVA-731923-plain-text';
const probe = '<svg onload=window.__fvaProbe=731923>';
const sql = ["')) AND 1=2 -- ", "')) OR 1=1 -- "];
const controls = {domValues: [control, probe], searchValues: [control, probe, ...sql]};
const url = (origin, q) => origin + '/#/search?q=' + encodeURIComponent(q);

async function main() {
  const p = policy('http://127.0.0.1:3001', controls);
  assert(p.navigation(url('http://127.0.0.1:3001', probe)));
  assert(p.request('http://127.0.0.1:3001/rest/products/search?q=' + encodeURIComponent(sql[0]), 'GET'));
  for (const raw of ['http://127.0.0.1:3002/', 'http://localhost:3001/',
      'http://user@127.0.0.1:3001/', 'https://127.0.0.1:3001/',
      'http://127.0.0.1:3001/api/Users', 'http://127.0.0.1:3001/?extra=1',
      'http://127.0.0.1:3001/rest/products/search?q=x',
      'http://127.0.0.1:3001/rest/products/search?q=' + encodeURIComponent(control) + '&q=' + encodeURIComponent(probe)]) {
    assert(!p.request(raw, 'GET'));
  }
  assert(!p.request('http://127.0.0.1:3001/', 'POST'));
  assert(!p.navigation(url('http://127.0.0.1:3001', '<script>unapproved</script>')));
  assert(!p.navigation(url('http://127.0.0.1:3001', control) + '&extra=1'));
  assert.throws(() => policy('http://localhost:3001', controls));
  assert.throws(() => broker(p, {maxRequests: 1501}));
  let allowedHits = 0, deniedHits = 0, upgrades = 0;
  const deny = http.createServer((req, res) => { deniedHits++; res.end('unapproved'); });
  deny.on('upgrade', (req, socket) => { upgrades++; socket.destroy(); });
  await new Promise(resolve => deny.listen(0, '127.0.0.1', resolve));
  const deniedOrigin = `http://127.0.0.1:${deny.address().port}`;
  const fixture = http.createServer((req, res) => {
    allowedHits++;
    if (req.url === '/rest/languages') {
      res.writeHead(302, {Location: deniedOrigin}); res.end();
    } else if (req.url === '/api/Categories') {
      res.end('x'.repeat(10000));
    } else {
      res.setHeader('Content-Type', 'text/html');
      res.end(`<div id="output"></div><script>
        const q=new URLSearchParams(location.hash.split('?')[1]).get('q');
        document.getElementById('output').innerHTML=q;
      </script>`);
    }
  });
  await new Promise(resolve => fixture.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${fixture.address().port}`;
  const scoped = policy(origin, controls);
  const transport = broker(scoped, {maxRequests: 3, maxBytes: 4096});
  let guard;
  try {
    await assert.rejects(transport.get(origin + '/rest/languages', 'GET'));
    await assert.rejects(transport.get(origin + '/api/Categories', 'GET'));
    await transport.get(origin + '/', 'GET');
    await assert.rejects(transport.get(origin + '/', 'GET'));
    assert.equal(allowedHits, 3); assert.equal(deniedHits, 0);
    assert.equal(transport.stats.responseRejected, 2);
    assert.equal(transport.stats.rejected, 1);
    if (process.env.FVA_PLAYWRIGHT_MODULE && process.env.FVA_BROWSER_EXECUTABLE) {
      const playwright = require(process.env.FVA_PLAYWRIGHT_MODULE);
      guard = await createLocalBoundary(playwright, process.env.FVA_BROWSER_EXECUTABLE,
        origin, controls, {maxRequests: 30, maxBytes: 4096});
      const first = await guard.open(url(origin, control));
      assert.equal(await first.page.evaluate(() => window.__fvaProbe), undefined);
      await first.close();
      const second = await guard.open(url(origin, probe));
      await second.page.waitForFunction(() => window.__fvaProbe === 731923);
      await assert.rejects(guard.open(url(origin, 'unapproved-fragment')));
    const before = allowedHits;
      const blocked = await second.page.evaluate(async ({origin, deniedOrigin}) => {
        const attempts = [fetch(deniedOrigin), fetch(origin + '/', {method: 'POST'}),
          fetch(origin + '/api/Users'), fetch(origin + '/rest/languages'),
          fetch(origin + '/api/Categories')];
        return (await Promise.allSettled(attempts)).map(r => r.status);
      }, {origin, deniedOrigin});
      assert(blocked.every(status => status === 'rejected'));
      assert.equal(allowedHits - before, 2); // Only redirect/size fixture GETs reach origin.
      const workerBlocked = await second.page.evaluate(async () => {
        try {
          const registration = await navigator.serviceWorker.register('/sw.js');
          return !registration?.active;
        }
        catch { return true; }
      });
      assert(workerBlocked);
      assert.equal(second.page.context().serviceWorkers().length, 0);
      assert.equal(allowedHits - before, 2);
      await second.page.evaluate(({deniedOrigin}) => {
        new WebSocket(deniedOrigin.replace('http:', 'ws:'));
        window.open(deniedOrigin);
        const f=document.createElement('iframe'); f.src=deniedOrigin; document.body.appendChild(f);
        navigator.sendBeacon(deniedOrigin, 'fixture');
      }, {deniedOrigin});
      await second.page.waitForTimeout(500);
      assert.equal(deniedHits, 0); assert.equal(upgrades, 0);
      assert(guard.stats.socketBlocked >= 1);
      assert(guard.stats.navigationBlocked >= 1);
      await second.close();
      console.log('Browser controls executed; service worker blocked; unapproved fixture received zero requests/upgrades');
    }
    console.log('Policy, redirect, response-size and request-budget checks passed');
  } finally {
    transport.close();
    if (guard) await guard.close();
    await Promise.all([fixture, deny].map(server => new Promise(resolve => server.close(resolve))));
  }
}
main().catch(error => { console.error('Boundary check failed:', error.message); process.exitCode = 1; });
