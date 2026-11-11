// VibeGuard API server (no dependencies). POST /api/audit {url}. Send "Accept: application/x-ndjson" to stream progress.
const http = require('http'), fs = require('fs'), path = require('path'), cfg = require('./config');
const { runAudit } = require('./audit/auditService'), { AuditError } = require('./errors');
const hits = new Map(); let active = 0;
const limited = ip => { const now = Date.now(), a = (hits.get(ip) || []).filter(t => now - t < 60000); a.push(now); hits.set(ip, a); return a.length > cfg.rateLimit; };
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (!v.some(t => now - t < 60000)) hits.delete(k); }, 60000).unref();
const clientIp = req => (cfg.trustProxy && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress;
const INDEX = path.join(__dirname, '..', '..', 'frontend', 'index.html');
const send = (res, status, obj) => { res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(obj)); };
const fail = (res, e) => { if (!(e instanceof AuditError)) { console.error('[audit] unexpected:', e); e = new AuditError('UNEXPECTED', 'Something unexpected happened while auditing that website.', 500); } send(res, e.status, { error: { code: e.code, message: e.message } }); };
function body(req, max = 4096) { return new Promise((ok, no) => { let s = ''; req.on('data', c => { s += c; if (s.length > max) { no(new AuditError('INVALID_URL', 'Request body too large.', 413)); req.destroy(); } }); req.on('end', () => ok(s)); req.on('error', no); }); }

const handler = async (req, res) => {
  // Dogfooding: the API sends the headers it recommends.
  res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'");
  // CORS: CORS_ORIGIN is a comma-separated allow-list; the matching request origin is echoed back.
  if (cfg.corsOrigins.length) { res.setHeader('Vary', 'Origin'); if (cfg.corsOrigins.includes(req.headers.origin)) { res.setHeader('Access-Control-Allow-Origin', req.headers.origin); res.setHeader('Access-Control-Allow-Headers', 'content-type'); res.setHeader('Access-Control-Allow-Methods', 'POST,GET,OPTIONS'); res.setHeader('Access-Control-Max-Age', '600'); } }
  const url = new URL(req.url, 'http://x');
  try {
    if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
    if (req.method === 'GET' && url.pathname === '/api/health') return send(res, 200, { ok: true });
    if (req.method === 'GET' && cfg.serveFrontend && (url.pathname === '/' || url.pathname === '/index.html')) {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }); return res.end(fs.readFileSync(INDEX));
    }
    if (req.method === 'POST' && url.pathname === '/api/audit') {
      if (limited(clientIp(req))) return fail(res, new AuditError('RATE_LIMITED', 'Too many audits from your connection. Wait a minute and try again.', 429));
      if (active >= cfg.maxConcurrent) return fail(res, new AuditError('RATE_LIMITED', 'The audit server is busy. Try again in a moment.', 429));
      let input; try { input = JSON.parse(await body(req)).url; } catch (e) { return fail(res, e instanceof AuditError ? e : new AuditError('INVALID_URL', 'Send JSON like {"url":"https://example.com"}.', 400)); }
      const stream = /ndjson/.test(req.headers.accept || ''); let started = false;
      const emit = ev => { if (!started) { started = true; res.writeHead(200, { 'content-type': 'application/x-ndjson', 'cache-control': 'no-store', 'x-accel-buffering': 'no' }); } res.write(JSON.stringify(ev) + '\n'); };
      active++;
      try {
        const data = await runAudit(input, stream ? emit : () => {});
        if (stream) { emit({ type: 'result', data }); res.end(); } else send(res, 200, data);
      } catch (e) {
        if (!stream) return fail(res, e);
        if (!(e instanceof AuditError)) { console.error('[audit] unexpected:', e); e = new AuditError('UNEXPECTED', 'Something unexpected happened while auditing that website.', 500); }
        emit({ type: 'error', error: { code: e.code, message: e.message } }); res.end();
      } finally { active--; }
      return;
    }
    send(res, 404, { error: { code: 'NOT_FOUND', message: 'Not found.' } });
  } catch (e) { fail(res, e); }
};

module.exports = handler; // used by the Vercel serverless function in /api

// Standalone mode (npm start): run as a long-lived server. Not started when imported by Vercel.
if (require.main === module) {
  http.createServer(handler).listen(cfg.port, () => console.log(`VibeGuard API listening on http://localhost:${cfg.port}${cfg.allowPrivate ? '  (ALLOW_PRIVATE_TARGETS=true: dev mode)' : ''}`));
}
