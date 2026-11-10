// checkMetadata: page metadata, external resources, robots.txt, security.txt, a few well-known exposed files
// (single read-only GET each, content-verified), and secrets accidentally shipped in the HTML/JS. Passive only.
const { fetchUrl } = require('../net/httpClient'), cfg = require('../config');
const tags = (html, n) => [...html.matchAll(new RegExp('<' + n + '\\b[^>]*>', 'gi'))].map(m => m[0]);
const attr = (t, a) => { const m = new RegExp('\\b' + a + '\\s*=\\s*(?:"([^"]*)"|\'([^\']*)\'|([^\\s>]+))', 'i').exec(t); return m ? (m[1] ?? m[2] ?? m[3]) : null; };
const isHtml = b => /^\s*<(!doctype|html|head|body)/i.test(b);
const SECRETS = [['AWS access key', /\bAKIA[0-9A-Z]{16}\b/g], ['Stripe live secret key', /\bsk_live_[0-9a-zA-Z]{16,}/g], ['Private key block', /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g],
  ['GitHub token', /\bgh[pousr]_[A-Za-z0-9]{36,}/g], ['OpenAI-style API key', /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}/g], ['Anthropic API key', /\bsk-ant-[A-Za-z0-9_-]{20,}/g], ['Slack token', /\bxox[baprs]-[A-Za-z0-9-]{10,}/g]];
const JWT = /eyJ[A-Za-z0-9_-]{8,}\.(eyJ[A-Za-z0-9_-]{8,})\.[A-Za-z0-9_-]{8,}/g;
const PROBES = [['/.env', 'critical', b => /^[A-Z][A-Z0-9_]{2,}=.+/m.test(b) && !isHtml(b), b => 'contains variables: ' + [...b.matchAll(/^([A-Z][A-Z0-9_]{2,})=/gm)].slice(0, 5).map(m => m[1]).join(', ') + ' (values hidden)'],
  ['/.git/HEAD', 'critical', b => /^ref: refs\//.test(b), () => 'repository metadata is downloadable'], ['/.git/config', 'critical', b => /\[core\]/.test(b), () => 'git config is downloadable'],
  ['/.npmrc', 'high', b => /_authToken|registry\s*=/.test(b) && !isHtml(b), () => 'npm config is downloadable'], ['/.DS_Store', 'medium', b => b.startsWith('\u0000\u0000\u0000\u0001Bud1'), () => 'macOS directory listing file is downloadable'],
  ['/phpinfo.php', 'high', b => /phpinfo\(\)|PHP Version/i.test(b), () => 'phpinfo() output is public'], ['/server-status', 'medium', b => /Apache Server Status/i.test(b), () => 'Apache status page is public']];
const redact = s => s.slice(0, 6) + '…[redacted]';

async function checkMetadata(ctx) {
  const f = [], body = ctx.page.body, origin = ctx.finalUrl.origin, insecure = !!ctx.certProblem;
  const get = async (p, max = 65536, follow = false) => { try { return await fetchUrl(new URL(p, origin).href, { follow, maxBytes: max, insecure }); } catch { return null; } };
  const html = isHtml(body) ? body : '';
  // 1) Page metadata
  const title = (/<title[^>]*>([\s\S]*?)<\/title>/i.exec(html) || [])[1], metas = tags(html, 'meta');
  const m = n => { const t = metas.find(x => (attr(x, 'name') || '').toLowerCase() === n); return t ? attr(t, 'content') : null; };
  const meta = { title: title && title.trim().slice(0, 120), description: m('description') && m('description').slice(0, 160), generator: m('generator') };
  f.push({ key: 'info', title: 'Page metadata', category: 'HTTP Security', evidence: `Title: ${meta.title || '(none)'}\nDescription: ${meta.description || '(none)'}${meta.generator ? '\nGenerator: ' + meta.generator : ''}`,
    description: 'Basic metadata read from the home page.', vibe: 'This is just what search engines and browsers see about your page.', recommendation: 'Make sure the generator tag and title do not reveal internal tooling you want private.' });
  // 2) External resources + SRI + mixed content
  const scripts = tags(html, 'script').map(t => ({ src: attr(t, 'src'), sri: attr(t, 'integrity') })).filter(s => s.src);
  const links = tags(html, 'link').filter(t => /stylesheet/i.test(attr(t, 'rel') || '')).map(t => attr(t, 'href')).filter(Boolean);
  const res = u => { try { return new URL(u, ctx.finalUrl); } catch { return null; } };
  const ext = new Set(), noSri = [], mixed = [];
  for (const s of scripts) { const u = res(s.src); if (!u) continue; if (u.hostname !== ctx.finalUrl.hostname) { ext.add(u.hostname); if (!s.sri) noSri.push(u.href); } if (ctx.httpsAvailable && u.protocol === 'http:') mixed.push(u.href); }
  for (const l of links) { const u = res(l); if (!u) continue; if (u.hostname !== ctx.finalUrl.hostname) ext.add(u.hostname); if (ctx.httpsAvailable && u.protocol === 'http:') mixed.push(u.href); }
  if (noSri.length) f.push({ key: 'external_no_sri', evidence: `${noSri.length} external script(s) without integrity:\n` + noSri.slice(0, 5).join('\n') });
  if (mixed.length) f.push({ key: 'mixed_content', evidence: 'Insecure http:// resources on an HTTPS page:\n' + mixed.slice(0, 5).join('\n') });
  if (ext.size) f.push({ key: 'info', title: 'External resources', category: 'Client-Side Security', evidence: `Loads scripts/styles from ${ext.size} other origin(s): ${[...ext].slice(0, 8).join(', ')}`,
    description: 'Third-party code runs with full access to your page.', vibe: 'Every outside script is a guest in your house. Only invite ones you trust.', recommendation: 'Keep third-party scripts to a minimum and pin versions with SRI hashes.' });
  if (!ctx.httpsAvailable && /<input[^>]+type\s*=\s*["']?password/i.test(html)) f.push({ key: 'password_http', evidence: 'A password field was found on a page served over HTTP.' });
  // 3) robots.txt + security.txt
  const rb = await get('/robots.txt', 65536, true), rok = rb && rb.status === 200 && !isHtml(rb.body);
  const dis = rok ? [...rb.body.matchAll(/^\s*disallow:\s*(\S+)/gim)].map(x => x[1]) : [], sens = dis.filter(p => /admin|internal|private|backup|staging|\.git|secret|dashboard/i.test(p));
  f.push({ key: 'info', title: rok ? 'robots.txt found' : 'No robots.txt found', category: 'Cloud Configuration', evidence: rok ? `${dis.length} Disallow rule(s)${sens.length ? '. Possibly sensitive paths listed: ' + sens.slice(0, 5).join(', ') : ''}` : '/robots.txt did not return a robots file.',
    description: 'robots.txt tells crawlers what to skip, and also tells people where interesting paths are.', vibe: sens.length ? 'Your robots.txt points at private-sounding pages. That is a signpost, not a lock.' : 'robots.txt is a note for search engines, not a security tool.', recommendation: 'Never rely on robots.txt to hide pages. Protect them with authentication.' });
  let st = await get('/.well-known/security.txt', 16384, true); if (!(st && st.status === 200 && /contact:/i.test(st.body))) st = await get('/security.txt', 16384, true);
  const sok = st && st.status === 200 && /contact:/i.test(st.body);
  f.push({ key: 'info', title: sok ? 'security.txt found' : 'No security.txt published', category: 'Cloud Configuration', evidence: sok ? 'A security.txt with a Contact field is published.' : 'Neither /.well-known/security.txt nor /security.txt was found.',
    description: 'security.txt (RFC 9116) tells researchers how to report vulnerabilities.', vibe: 'It is a "found a bug? email me here" sign for friendly hackers.', recommendation: 'Publish /.well-known/security.txt with a Contact address.' });
  // 4) Public configuration mistakes (one GET each, content-verified so SPA catch-alls do not false-positive)
  for (let i = 0; i < PROBES.length; i += 4) {
    const rs = await Promise.all(PROBES.slice(i, i + 4).map(([p]) => get(p, 4096)));
    rs.forEach((r, j) => { const [p, sev, test, desc] = PROBES[i + j]; if (r && r.status === 200 && test(r.body)) f.push({ key: 'exposed_file', dedupe: 'exposed_file:' + p, severity: sev, area: p, title: `Publicly accessible ${p}`, evidence: `GET ${p} returned HTTP 200 and ${desc(r.body)}.` }); });
  }
  // 5) Secrets in HTML + same-origin scripts (max 5 files)
  const srcs = [{ where: 'home page HTML', text: body }];
  for (const s of scripts.slice(0, 40)) { const u = res(s.src); if (u && u.origin === origin && srcs.length < 6) { try { const r = await fetchUrl(u.href, { follow: false, insecure, maxBytes: cfg.maxBytes }); if (r.status === 200) srcs.push({ where: u.pathname, text: r.body }); } catch {} } }
  const hits = [];
  for (const s of srcs) {
    for (const [n, re] of SECRETS) for (const x of s.text.matchAll(re)) hits.push(`${n} in ${s.where}: ${n === 'Private key block' ? '-----BEGIN…' : redact(x[0])}`);
    for (const x of s.text.matchAll(JWT)) { try { if (JSON.parse(Buffer.from(x[1], 'base64url').toString()).role === 'service_role') hits.push(`Supabase service_role key in ${s.where}: ${redact(x[0])}`); } catch {} }
  }
  if (hits.length) f.push({ key: 'secret_in_source', evidence: [...new Set(hits)].slice(0, 6).join('\n'), area: 'Public HTML / JavaScript' });
  return { findings: f, metadata: { ...meta, externalOrigins: [...ext], robotsTxt: !!rok, securityTxt: !!sok } };
}
module.exports = { checkMetadata };
