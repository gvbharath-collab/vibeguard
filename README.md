# VibeGuard

Passive security audits for vibe-coded websites. The UI is unchanged; it now calls a real backend.

```
URL -> POST /api/audit -> validate -> passive checks -> score -> vulnerabilities -> report UI
```

## Run it (Node 18+, no dependencies to install)

```bash
cd backend
cp .env.example .env      # optional, defaults work
npm start                 # API + frontend on http://localhost:8787
```
Open http://localhost:8787, enter a site you own (or `https://example.com`) and click **Start Security Audit**.

**Frontend separately:** `frontend/index.html` is static. Serve it from anywhere, set `<meta name="vg-api" content="http://localhost:8787">` in its `<head>`, and set `CORS_ORIGIN` in the backend `.env` to the frontend's origin.

**Try it on something vulnerable, locally:**
```bash
cd backend && npm run fixture                       # insecure demo site on :8081
ALLOW_PRIVATE_TARGETS=true npm start                # DEV ONLY: lets the scanner reach localhost
# audit http://localhost:8081
```

## Environment variables (`backend/.env`)
| Variable | Default | Purpose |
|---|---|---|
| PORT | 8787 | API port |
| AUDIT_TIMEOUT_MS / AUDIT_TOTAL_TIMEOUT_MS | 8000 / 45000 | per-request / whole-audit timeouts |
| AUDIT_MAX_BYTES | 1048576 | max response body read per request |
| AUDIT_MAX_REDIRECTS | 5 | redirect limit |
| RATE_LIMIT_PER_MIN | 5 | audits per client IP per minute |
| MAX_CONCURRENT_AUDITS | 5 | simultaneous audits |
| CORS_ORIGIN | (empty) | allowed frontend origin when served separately |
| SERVE_FRONTEND | true | serve `frontend/index.html` at `/` |
| TRUST_PROXY | false | use `X-Forwarded-For` (only behind your own proxy) |
| ALLOW_PRIVATE_TARGETS | false | dev only: allow localhost/private targets |

No secrets are needed or stored.

## API
`POST /api/audit` with `{"url":"https://example.com"}` returns `{target, scannedAt, score, riskLevel, summary, categories, vulnerabilities[], metadata}`.
Each vulnerability has `id, title, severity, category, description, technicalExplanation, vibeCoderExplanation, evidence, recommendation, references` plus `key, affectedArea, whyItMatters, fixExample, avoid, verification`.
Send `Accept: application/x-ndjson` to stream `{"type":"stage","index":n}` progress events, then a final `{"type":"result"}` or `{"type":"error"}` line.
Errors are `{error:{code,message}}` with user-safe messages (`INVALID_URL, BLOCKED_TARGET, DNS_FAILURE, TIMEOUT, UNREACHABLE, SSL_ERROR, BLOCKED, RATE_LIMITED, UNEXPECTED_RESPONSE, UNEXPECTED`). Raw errors are only logged server-side. `GET /api/health` returns `{ok:true}`.

## Architecture (`backend/src`)
```
server.js            HTTP API, rate limit, streaming
audit/auditService   orchestrator (stage order lives here)
 ├ validateUrl       syntax, scheme, ports, hostname + DNS checks
 ├ checkHttps        fetch target, HTTPS availability, HTTP->HTTPS redirect
 ├ checkTls          one TLS handshake: protocol, cipher, certificate validity/expiry
 ├ checkHeaders      CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer/Permissions-Policy, CORS
 ├ checkCookies      Secure / HttpOnly / SameSite (values never stored)
 ├ checkTechnology   server/stack fingerprint, version + debug header leaks
 ├ checkMetadata     page metadata, external scripts/SRI, mixed content, robots.txt, security.txt,
 │                   well-known exposed files, secrets in public HTML/JS
 ├ findings          catalog of titles + plain-English explanations -> vulnerability objects
 └ calculateScore    severity weights (25/12/6/2/0), risk level, summary, categories
net/httpClient       timeouts, size cap, manual redirects      net/ssrf   private-IP blocking
```
To add a check: write a function returning `{key, evidence}` items and add a catalog entry in `findings.js`.

## Safety model
Passive and read-only: GET/HEAD requests and one TLS handshake. No brute force, credential attempts, fuzzing, exploitation, port scanning or load. About 25 requests per audit. The well-known-file probes request each path once and only report when the content matches the file's signature. Secret values are redacted in evidence.
SSRF defenses: localhost, private, link-local, metadata (169.254.169.254) and IPv6 internal ranges are blocked at validation and again at connect time on every redirect hop (this also stops DNS rebinding); only ports 80/443/8080/8443; no URL credentials; redirect, size and time limits; per-IP rate limiting.

## Limitations
- Passive means no proof of exploitability: it finds missing protections and exposed data, not logic bugs, SQL injection, broken access control or business-logic flaws.
- Only the home page and up to 5 same-origin scripts are analysed; client-rendered content and authenticated areas are not.
- TLS checks cover validity and expiry, not full cipher/protocol grading. Dependency, database and cloud-config checks need repository or credential access and are not included.
- The GitHub tab is not implemented yet. The rate limiter is in-memory (single instance).
- Only scan websites and applications you own or are authorized to test.
