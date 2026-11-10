// checkTechnology: fingerprints the stack from headers + HTML and flags version/debug disclosure.
function checkTechnology(ctx) {
  const h = ctx.page.headers, body = ctx.page.body, f = [], tech = new Set();
  if (h.server && /\d+\.\d+/.test(h.server)) f.push({ key: 'server_banner', evidence: `Server: ${h.server}` });
  for (const k of ['x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator'])
    if (h[k]) f.push({ key: 'powered_by', area: k, evidence: `${k}: ${h[k]}` });
  const dbg = Object.keys(h).filter(k => /^(x-debug|x-backend|x-source|x-php-version|x-runtime)/.test(k) || /\b(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)\b/.test(String(h[k])));
  if (dbg.length) f.push({ key: 'debug_headers', evidence: dbg.slice(0, 5).map(k => `${k}: ${String(h[k]).slice(0, 80)}`).join('\n') });
  if (h.server) tech.add(h.server.split('/')[0]);
  if (h['x-vercel-id']) tech.add('Vercel'); if (h['x-nf-request-id']) tech.add('Netlify'); if (h['cf-ray']) tech.add('Cloudflare');
  if (/\/_next\//.test(body)) tech.add('Next.js'); if (/wp-content|wp-includes/.test(body)) tech.add('WordPress');
  if (/cdn\.shopify\.com/.test(body)) tech.add('Shopify'); if (/[a-z0-9]{10,}\.supabase\.co/.test(body)) tech.add('Supabase'); if (/firebaseio\.com|firebaseapp\.com/.test(body)) tech.add('Firebase');
  const technologies = [...tech];
  if (technologies.length) f.push({ key: 'info', title: 'Detected technologies', category: 'HTTP Security', evidence: technologies.join(', '),
    description: 'Technologies visible from public responses.', vibe: 'These are the tools your site openly announces. Fine to be visible, but make sure each one is configured safely (for example Supabase or Firebase rules).', recommendation: 'Review the security settings of each detected service.' });
  return { findings: f, technologies };
}
module.exports = { checkTechnology };
