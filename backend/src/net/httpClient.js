// Minimal, safe HTTP client: timeout, body-size cap, manual redirects, SSRF-guarded DNS. GET/HEAD only.
const http = require('http'), https = require('https'), cfg = require('../config');
const { guardedLookup } = require('./ssrf'), { AuditError } = require('../errors');
const UA = 'VibeGuard-Passive-Audit/1.0 (+authorized security self-assessment)';

function once(u, { method, maxBytes, insecure }) {
  return new Promise((resolve, reject) => {
    const lib = u.protocol === 'https:' ? https : http;
    let done = false, timer;
    const fin = (f, v) => { if (!done) { done = true; clearTimeout(timer); f(v); } };
    const req = lib.request(u, { method, lookup: guardedLookup, agent: false, rejectUnauthorized: !insecure,
      headers: { 'user-agent': UA, accept: 'text/html,application/xhtml+xml,*/*;q=0.8' } }, res => {
      const chunks = []; let size = 0, truncated = false;
      const build = () => ({ status: res.statusCode, headers: res.headers, setCookie: res.headers['set-cookie'] || [], body: Buffer.concat(chunks).toString('utf8'), truncated });
      res.on('data', c => {
        size += c.length;
        if (size > maxBytes) { truncated = true; chunks.push(c.subarray(0, c.length - (size - maxBytes))); res.destroy(); fin(resolve, build()); }
        else chunks.push(c);
      });
      res.on('end', () => fin(resolve, build()));
      res.on('error', e => fin(reject, e));
    });
    timer = setTimeout(() => { const e = new Error('timeout'); e.code = 'AUDIT_TIMEOUT'; req.destroy(); fin(reject, e); }, cfg.timeoutMs);
    req.on('error', e => fin(reject, e));
    req.end();
  });
}

async function fetchUrl(href, { method = 'GET', follow = true, maxBytes = cfg.maxBytes, insecure = false } = {}) {
  let u = new URL(href); const redirects = [];
  for (let i = 0; i <= cfg.maxRedirects; i++) {
    if (!['http:', 'https:'].includes(u.protocol)) throw new AuditError('INVALID_URL', 'Redirected to an unsupported protocol.');
    const r = await once(u, { method, maxBytes, insecure });
    const loc = r.headers.location;
    if (follow && [301, 302, 303, 307, 308].includes(r.status) && loc) {
      const next = new URL(loc, u); redirects.push({ from: u.href, status: r.status, to: next.href }); u = next; continue;
    }
    return { ...r, url: u.href, redirects };
  }
  const e = new Error('redirects'); e.code = 'TOO_MANY_REDIRECTS'; throw e;
}
module.exports = { fetchUrl };
