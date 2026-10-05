'use strict';

// Local control runner only. This does not install a guard in Polaris's browser
// or produce runtime approval/confirmation evidence.
const http = require('node:http');
const {performance} = require('node:perf_hooks');

function policy(origin, {domValues, searchValues, assets = []}) {
  const base = new URL(origin);
  if (base.protocol !== 'http:' || base.hostname !== '127.0.0.1' ||
      base.username || base.password || base.pathname !== '/' || base.search || base.hash) {
    throw new Error('A numeric IPv4 loopback HTTP origin is required');
  }
  const neutral = new Set(['/', '/rest/admin/application-configuration',
    '/rest/languages', '/api/Challenges', '/api/Categories', ...assets]);
  const dom = new Set(domValues);
  const queries = new Set(searchValues);
  if (!dom.size || !queries.size || [...dom, ...queries].some(v =>
      typeof v !== 'string' || v.length > 200)) throw new Error('Invalid exact controls');
  function sameOrigin(url) {
    return url.origin === base.origin && !url.username && !url.password;
  }
  function oneQuery(params, values) {
    return [...params].length === 1 && params.has('q') && values.has(params.get('q'));
  }
  return {
    navigation(raw) {
      try {
        const u = new URL(raw);
        if (!sameOrigin(u) || u.pathname !== '/' || u.search) return false;
        const fragment = u.hash.slice(1);
        const split = fragment.indexOf('?');
        return fragment.slice(0, split) === '/search' && split >= 0 &&
          oneQuery(new URLSearchParams(fragment.slice(split + 1)), dom);
      } catch { return false; }
    },
    request(raw, method) {
      try {
        const u = new URL(raw);
        if (!sameOrigin(u) || method !== 'GET' || u.hash) return false;
        if (u.pathname === '/rest/products/search') return oneQuery(u.searchParams, queries);
        return neutral.has(u.pathname) && !u.search;
      } catch { return false; }
    },
  };
}

function broker(check, {maxRequests = 1500, maxBytes = 1048576,
    minutes = 15, requestsPerSecond = 2} = {}) {
  if (!Number.isInteger(maxRequests) || maxRequests < 1 || maxRequests > 1500 ||
      !Number.isInteger(maxBytes) || maxBytes < 1 || maxBytes > 1048576 ||
      !(minutes > 0 && minutes <= 15) ||
      !(requestsPerSecond > 0 && requestsPerSecond <= 2)) throw new Error('Invalid limits');
  const until = performance.now() + minutes * 60000;
  const stats = {forwarded: 0, rejected: 0, responseRejected: 0};
  let reserved = 0, next = 0, closed = false;
  const waiting = new Map();
  const sockets = new Set();
  const agent = new http.Agent({maxSockets: 2});
  async function get(url, method) {
    if (closed || !check.request(url, method) || reserved >= maxRequests || performance.now() >= until) {
      stats.rejected++; throw new Error('Request denied');
    }
    reserved++;
    const delay = Math.max(0, next - performance.now());
    next = performance.now() + delay + 1000 / requestsPerSecond;
    await new Promise(resolve => {
      const timer = setTimeout(() => { waiting.delete(timer); resolve(); }, delay);
      waiting.set(timer, resolve);
    });
    if (closed || performance.now() >= until) { stats.rejected++; throw new Error('Deadline reached'); }
    return new Promise((resolve, reject) => {
      const req = http.get(url, {agent, headers: {'Accept-Encoding': 'identity'}}, res => {
        if (res.statusCode >= 300 && res.statusCode < 400 ||
            Number(res.headers['content-length']) > maxBytes ||
            (res.headers['content-encoding'] && res.headers['content-encoding'] !== 'identity')) {
          stats.responseRejected++; res.destroy(); reject(new Error('Response denied')); return;
        }
        const chunks = []; let bytes = 0;
        res.on('data', chunk => {
          bytes += chunk.length;
          if (bytes > maxBytes) {
            stats.responseRejected++; res.destroy(); reject(new Error('Response too large'));
          } else chunks.push(chunk);
        });
        res.on('error', () => reject(new Error('Response failed')));
        res.on('end', () => {
          const headers = {...res.headers};
          for (const name of ['connection', 'transfer-encoding', 'content-length',
              'set-cookie', 'refresh', 'location']) delete headers[name];
          resolve({status: res.statusCode, headers, body: Buffer.concat(chunks)});
        });
      });
      stats.forwarded++;
      sockets.add(req); req.on('close', () => sockets.delete(req));
      const timer = setTimeout(() => req.destroy(),
        Math.min(10000, Math.max(1, until - performance.now())));
      req.on('close', () => clearTimeout(timer));
      req.on('error', () => reject(new Error('Local request failed')));
    });
  }
  return {get, stats, close() {
    closed = true;
    for (const [timer, resolve] of waiting) { clearTimeout(timer); resolve(); }
    waiting.clear();
    for (const req of sockets) req.destroy();
    agent.destroy();
  }};
}

async function createLocalBoundary(playwright, executablePath, origin, controls, limits) {
  const check = policy(origin, controls);
  const transport = broker(check, limits);
  // Any traffic not intercepted below encounters a proxy that never forwards.
  const denyProxy = http.createServer((req, res) => { res.writeHead(403); res.end(); });
  denyProxy.on('connect', (req, socket) => socket.destroy());
  await new Promise(resolve => denyProxy.listen(0, '127.0.0.1', resolve));
  let browser;
  try {
    browser = await playwright.chromium.launch({executablePath, headless: true,
      proxy: {server: `http://127.0.0.1:${denyProxy.address().port}`},
      args: ['--proxy-bypass-list=<-loopback>', '--disable-quic',
        '--disable-background-networking', '--dns-prefetch-disable',
        '--force-webrtc-ip-handling-policy=disable_non_proxied_udp']});
  } catch (error) {
    transport.close(); denyProxy.close(); throw new Error('Guarded browser launch failed');
  }
  const stats = {networkBlocked: 0, socketBlocked: 0, popupBlocked: 0, navigationBlocked: 0};
  const contexts = new Set();
  async function open(raw) {
    if (!check.navigation(raw)) { stats.navigationBlocked++; throw new Error('Navigation denied'); }
    const context = await browser.newContext({serviceWorkers: 'block',
      acceptDownloads: false, offline: true});
    contexts.add(context);
    let main, documentRequested = false;
    context.on('page', page => {
      if (main && page !== main) { stats.popupBlocked++; page.close().catch(() => {}); }
    });
    await context.routeWebSocket(/.*/, ws => { stats.socketBlocked++; ws.close(); });
    await context.route(/.*/, async route => {
      const request = route.request();
      if (request.isNavigationRequest()) {
        if (documentRequested || request.frame().parentFrame() || request.frame().page() !== main) {
          stats.networkBlocked++; await route.abort(); return;
        }
        documentRequested = true;
      }
      try {
        const reply = await transport.get(request.url(), request.method());
        await route.fulfill(reply);
      } catch {
        stats.networkBlocked++; await route.abort().catch(() => {});
      }
    });
    main = await context.newPage();
    // One exact initial fragment per fresh context; no interactive scan driver.
    await main.goto(raw, {waitUntil: 'domcontentloaded', timeout: 10000});
    return {page: main, close: async () => { contexts.delete(context); await context.close(); }};
  }
  return {open, stats, transportStats: transport.stats, async close() {
    transport.close();
    await Promise.all([...contexts].map(c => c.close()));
    await browser.close();
    await new Promise(resolve => denyProxy.close(resolve));
  }};
}

module.exports = {policy, broker, createLocalBoundary};
