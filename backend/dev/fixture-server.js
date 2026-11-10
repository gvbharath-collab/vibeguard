// A deliberately insecure local site for testing VibeGuard end to end. DEV ONLY.
// Run: npm run fixture   then start the API with ALLOW_PRIVATE_TARGETS=true and audit http://localhost:8081
const http = require('http');
http.createServer((req, res) => {
  if (req.url === '/.env') { res.writeHead(200, { 'content-type': 'text/plain' }); return res.end('DATABASE_URL=postgres://u:p@h/db\nSTRIPE_KEY=abc\n'); }
  if (req.url === '/robots.txt') { res.writeHead(200, { 'content-type': 'text/plain' }); return res.end('User-agent: *\nDisallow: /admin\nDisallow: /internal-api\n'); }
  if (req.url === '/app.js') { res.writeHead(200, { 'content-type': 'text/javascript' }); return res.end('const k="sk_live_51N9aBcDeFgHiJkLmNoPqRs";'); }
  res.writeHead(200, { 'content-type': 'text/html', server: 'nginx/1.18.0', 'x-powered-by': 'Express', 'set-cookie': ['session_id=abc123; Path=/', 'theme=dark'], 'access-control-allow-origin': '*' });
  res.end('<!doctype html><html><head><title>Vibe Todo</title><meta name="description" content="A todo app"><script src="/app.js"></script><script src="https://cdn.example.org/lib.js"></script></head><body><form><input type="password"></form></body></html>');
}).listen(8081, () => console.log('Fixture (insecure on purpose) on http://localhost:8081'));
