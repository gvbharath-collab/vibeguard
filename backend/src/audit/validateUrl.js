// validateUrl: syntax, scheme, credentials, port, hostname and DNS checks. Blocks localhost / private / metadata targets.
const net = require('net'), dns = require('dns'), cfg = require('../config');
const { AuditError, mapNetError } = require('../errors'), { isPrivateIp, blocked } = require('../net/ssrf');
const BLOCKED_HOST = /^(localhost|.*\.localhost|.*\.local|.*\.internal|.*\.lan|.*\.home\.arpa)$/i;
const bad = m => new AuditError('INVALID_URL', m, 400);
async function validateUrl(input) {
  if (typeof input !== 'string' || !input.trim() || input.length > 2048) throw bad('Enter a full website address, like https://your-site.com.');
  let raw = input.trim(); if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) raw = 'https://' + raw;
  let u; try { u = new URL(raw); } catch { throw bad("That doesn't look like a valid URL. Include the domain, e.g. https://your-site.com."); }
  if (!['http:', 'https:'].includes(u.protocol)) throw bad('Only http:// and https:// addresses can be audited.');
  if (u.username || u.password) throw bad('Remove the username/password from the URL.');
  const port = u.port ? Number(u.port) : (u.protocol === 'https:' ? 443 : 80);
  if (!cfg.allowPrivate && ![80, 443, 8080, 8443].includes(port)) throw bad('Only ports 80, 443, 8080 and 8443 can be audited.');
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(host)) { if (!cfg.allowPrivate && isPrivateIp(host)) throw blocked(); }
  else {
    if (!cfg.allowPrivate && (BLOCKED_HOST.test(host) || !host.includes('.'))) throw blocked();
    let addrs; try { addrs = await dns.promises.lookup(host, { all: true }); } catch (e) { throw mapNetError(e); }
    if (!cfg.allowPrivate && addrs.some(a => isPrivateIp(a.address))) throw blocked();
  }
  u.hash = '';
  return { url: u, hostname: host, port };
}
module.exports = { validateUrl };
