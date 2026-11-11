// Central configuration. Reads backend/.env (tiny loader, no dependencies) then process.env.
const fs = require('fs'), path = require('path');
try {
  for (const l of fs.readFileSync(path.join(__dirname, '..', '.env'), 'utf8').split(/\r?\n/)) {
    const m = /^\s*([A-Z0-9_]+)\s*=\s*([^#]*?)\s*(?:#.*)?$/.exec(l);
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2];
  }
} catch {}
const n = (k, d) => Number(process.env[k] || d);
module.exports = {
  port: n('PORT', 8787), timeoutMs: n('AUDIT_TIMEOUT_MS', 8000), totalTimeoutMs: n('AUDIT_TOTAL_TIMEOUT_MS', 45000),
  maxBytes: n('AUDIT_MAX_BYTES', 1048576), maxRedirects: n('AUDIT_MAX_REDIRECTS', 5),
  rateLimit: n('RATE_LIMIT_PER_MIN', 5), maxConcurrent: n('MAX_CONCURRENT_AUDITS', 5),
  corsOrigins: (process.env.CORS_ORIGIN || '').split(',').map(x => x.trim().replace(/\/$/, '')).filter(Boolean), serveFrontend: process.env.SERVE_FRONTEND !== 'false',
  trustProxy: process.env.TRUST_PROXY === 'true', allowPrivate: process.env.ALLOW_PRIVATE_TARGETS === 'true',
};
