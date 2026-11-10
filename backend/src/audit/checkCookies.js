// checkCookies: parses Set-Cookie headers. Cookie values are never stored or shown, only names and attributes.
const SESSION = /sess|auth|token|jwt|sid|login|csrf/i;
function checkCookies(ctx) {
  const groups = { secure: [], httponly: [], samesite: [] };
  for (const raw of ctx.page.setCookie) {
    const parts = raw.split(';').map(s => s.trim()), name = parts[0].split('=')[0], a = parts.slice(1).map(s => s.toLowerCase());
    const ss = a.find(x => x.startsWith('samesite=')), s = SESSION.test(name);
    if (ctx.httpsAvailable && !a.includes('secure')) groups.secure.push({ name, s });
    if (!a.includes('httponly')) groups.httponly.push({ name, s });
    if (!ss) groups.samesite.push({ name, s }); else if (ss === 'samesite=none' && !a.includes('secure')) groups.secure.push({ name, s, none: true });
  }
  const f = [], ev = (l, t) => l.map(c => `Set-Cookie: ${c.name}=<hidden> is missing ${t}${c.none ? ' (SameSite=None requires Secure)' : ''}`).join('\n');
  const sev = l => l.some(c => c.s) ? 'medium' : 'low';
  if (groups.secure.length) f.push({ key: 'cookie_secure', severity: sev(groups.secure), evidence: ev(groups.secure, 'Secure') });
  if (groups.httponly.length) f.push({ key: 'cookie_httponly', severity: sev(groups.httponly), evidence: ev(groups.httponly, 'HttpOnly') });
  if (groups.samesite.length) f.push({ key: 'cookie_samesite', evidence: ev(groups.samesite, 'SameSite') });
  return f;
}
module.exports = { checkCookies };
