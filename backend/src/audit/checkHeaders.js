// checkHeaders: inspects security headers on the main response. Purely reads what the server already sent.
function checkHeaders(ctx) {
  const h = ctx.page.headers, f = [], where = ctx.finalUrl.href;
  const csp = h['content-security-policy'];
  if (!csp) f.push({ key: 'csp_missing', evidence: `No Content-Security-Policy header in the response from ${where}.` });
  else if (/(script-src|default-src)[^;]*('unsafe-inline'|'unsafe-eval'|\s\*(\s|;|$))/i.test(csp)) f.push({ key: 'csp_weak', evidence: `Content-Security-Policy: ${csp.slice(0, 220)}` });
  if (ctx.httpsAvailable) {
    const hsts = h['strict-transport-security'];
    if (!hsts) f.push({ key: 'hsts_missing', evidence: 'No Strict-Transport-Security header on the HTTPS response.' });
    else { const m = /max-age=(\d+)/i.exec(hsts); if (!m || +m[1] < 15552000) f.push({ key: 'hsts_weak', evidence: `Strict-Transport-Security: ${hsts} (max-age under 180 days).` }); }
  }
  if (!/nosniff/i.test(h['x-content-type-options'] || '')) f.push({ key: 'xcto_missing', evidence: `X-Content-Type-Options: ${h['x-content-type-options'] || '(absent)'}` });
  if (!h['x-frame-options'] && !/frame-ancestors/i.test(csp || '')) f.push({ key: 'xfo_missing', evidence: 'Neither X-Frame-Options nor CSP frame-ancestors is set.' });
  if (!h['referrer-policy']) f.push({ key: 'referrer_missing', evidence: 'No Referrer-Policy header.' });
  if (!h['permissions-policy'] && !h['feature-policy']) f.push({ key: 'permissions_missing', evidence: 'No Permissions-Policy header.' });
  const acao = h['access-control-allow-origin'];
  if (acao === '*' && String(h['access-control-allow-credentials']).toLowerCase() === 'true') f.push({ key: 'cors_credentials', evidence: 'Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true' });
  else if (acao === '*') f.push({ key: 'cors_wildcard', evidence: 'Access-Control-Allow-Origin: * on the main page response.' });
  return f;
}
module.exports = { checkHeaders };
