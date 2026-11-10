// SSRF protection. Every connection (including redirects) resolves DNS through guardedLookup,
// which rejects private/internal addresses at connect time. That also defeats DNS rebinding.
const net = require('net'), dns = require('dns'), cfg = require('../config'), { AuditError } = require('../errors');
function v4private(ip) {
  const [a, b, c] = ip.split('.').map(Number);
  return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || // 169.254/16 incl. cloud metadata
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 0 && c === 0) || (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) || a >= 224;
}
function isPrivateIp(ip) {
  if (net.isIPv4(ip)) return v4private(ip);
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase(), m = l.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (m) return v4private(m[1]);
    return l === '::' || l === '::1' || l.startsWith('::ffff:') || /^f[cd]/.test(l) || /^fe[89ab]/.test(l) || l.startsWith('64:ff9b:');
  }
  return true;
}
const blocked = () => new AuditError('BLOCKED_TARGET', "That address points to a private or internal network, so it can't be audited.", 400);
function guardedLookup(hostname, opts, cb) {
  if (typeof opts === 'function') { cb = opts; opts = {}; }
  dns.lookup(hostname, { ...opts, all: true }, (err, addrs) => {
    if (err) return cb(err);
    if (!cfg.allowPrivate && addrs.some(a => isPrivateIp(a.address))) return cb(blocked());
    if (opts.all) return cb(null, addrs);
    cb(null, addrs[0].address, addrs[0].family);
  });
}
module.exports = { isPrivateIp, guardedLookup, blocked };
