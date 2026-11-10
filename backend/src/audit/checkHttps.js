// checkHttps: fetches the target (HTTPS preferred), then tests HTTPS availability and the HTTP -> HTTPS redirect.
const { fetchUrl } = require('../net/httpClient'), { mapNetError, isCert } = require('../errors');

// Populates ctx.page / ctx.finalUrl / ctx.httpsAvailable. Cert errors still get audited (read-only) and reported later.
async function fetchTarget(ctx) {
  const u = ctx.target.url, cands = [];
  const variant = p => { const c = new URL(u.href); c.protocol = p; return c.href; };
  if (u.protocol === 'https:' || !u.port) cands.push(variant('https:'));
  if (u.protocol === 'http:' || !u.port) cands.push(variant('http:'));
  let firstErr = null;
  for (const href of cands) {
    try { ctx.page = await fetchUrl(href); }
    catch (e) {
      if (isCert(e.code) && href.startsWith('https:')) {
        try { ctx.page = await fetchUrl(href, { insecure: true }); ctx.certProblem = e.code; }
        catch (e2) { firstErr = firstErr || e2; continue; }
      } else { firstErr = firstErr || e; continue; }
    }
    break;
  }
  if (!ctx.page) throw mapNetError(firstErr);
  ctx.finalUrl = new URL(ctx.page.url);
  ctx.httpsAvailable = ctx.finalUrl.protocol === 'https:';
  if (!ctx.httpsAvailable && firstErr) ctx.httpsError = firstErr.code || 'connection failed';
}

async function checkHttps(ctx) {
  const f = [];
  if (!ctx.httpsAvailable) {
    f.push({ key: 'no_https', evidence: `${ctx.finalUrl.origin} is served over plain HTTP${ctx.httpsError ? ` (HTTPS attempt failed: ${ctx.httpsError})` : ''}.` });
    return f;
  }
  if (!ctx.target.url.port) { // standard ports only: probe http://host/ without following the redirect
    try {
      const r = await fetchUrl(`http://${ctx.finalUrl.hostname}/`, { follow: false, maxBytes: 2048 });
      const to = r.headers.location || '';
      if (r.status >= 300 && r.status < 400 && /^https:/i.test(new URL(to || '/', `http://${ctx.finalUrl.hostname}/`).href)) ctx.httpRedirects = true;
      else if (r.status < 400) f.push({ key: 'no_redirect', evidence: `GET http://${ctx.finalUrl.hostname}/ returned HTTP ${r.status} and did not redirect to HTTPS.` });
    } catch { /* port 80 closed: nothing to redirect */ }
  }
  return f;
}
module.exports = { fetchTarget, checkHttps };
