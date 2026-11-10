// checkTls: one ordinary TLS handshake to read protocol, cipher and certificate details. No probing of weak ciphers.
const tls = require('tls'), net = require('net'), cfg = require('../config'), { guardedLookup } = require('../net/ssrf');
function checkTls(ctx) {
  const none = { info: null, findings: [] };
  if (!ctx.httpsAvailable) return Promise.resolve(none);
  const host = ctx.finalUrl.hostname, port = Number(ctx.finalUrl.port) || 443;
  return new Promise(resolve => {
    let done = false; const fin = v => { if (!done) { done = true; resolve(v); } };
    const s = tls.connect({ host, port, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: false, lookup: guardedLookup, timeout: cfg.timeoutMs }, () => {
      const c = s.getPeerCertificate(), daysLeft = c.valid_to ? Math.floor((new Date(c.valid_to) - Date.now()) / 864e5) : null;
      const info = { protocol: s.getProtocol(), cipher: s.getCipher() && s.getCipher().name, authorized: s.authorized, authError: s.authorizationError || null,
        issuer: c.issuer && (c.issuer.O || c.issuer.CN), subject: c.subject && c.subject.CN, validTo: c.valid_to, daysLeft };
      s.end(); const f = [];
      if (!info.authorized) f.push({ key: 'tls_invalid', evidence: `Certificate verification failed: ${info.authError}. Subject: ${info.subject || 'n/a'}, issuer: ${info.issuer || 'n/a'}.` });
      else if (daysLeft !== null && daysLeft <= 30) f.push({ key: 'tls_expiry', severity: daysLeft <= 7 ? 'high' : 'medium', evidence: `Certificate expires ${c.valid_to} (${daysLeft} day(s) left).` });
      fin({ info, findings: f });
    });
    s.on('error', () => fin(none)); s.on('timeout', () => { s.destroy(); fin(none); });
  });
}
module.exports = { checkTls };
