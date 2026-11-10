// auditService: the central orchestrator.
//   validateUrl -> fetchTarget -> checkHttps/checkTls -> checkHeaders/checkTechnology -> checkCookies -> checkMetadata
//   -> generateVulnerabilities -> calculateScore.  Each check is a small module returning raw findings; all copy
//   lives in findings.js so a new check is: write a function, return {key, evidence}, add a catalog entry.
// To add a real active scanner later, add another check module here. Everything here is passive and read-only.
const { validateUrl } = require('./validateUrl'), { fetchTarget, checkHttps } = require('./checkHttps');
const { checkTls } = require('./checkTls'), { checkHeaders } = require('./checkHeaders'), { checkCookies } = require('./checkCookies');
const { checkTechnology } = require('./checkTechnology'), { checkMetadata } = require('./checkMetadata');
const { generateVulnerabilities } = require('./findings'), { calculateScore } = require('./calculateScore');
const { AuditError } = require('../errors'), cfg = require('../config');
const STAGES = ['connecting', 'fetching', 'https', 'headers', 'cookies', 'config', 'report'];

async function execute(input, onProgress) {
  const stage = i => onProgress({ type: 'stage', index: i, stage: STAGES[i] });
  stage(0); const ctx = { target: await validateUrl(input) };
  stage(1); await fetchTarget(ctx);
  const st = ctx.page.status;
  if (st === 403 || st === 429 || st === 401 && !ctx.page.body) throw new AuditError('BLOCKED', 'The website blocked or rate-limited our request, so it could not be audited. Allow-list the audit or try later.', 502);
  if (st >= 500) throw new AuditError('UNEXPECTED_RESPONSE', `The website returned a server error (HTTP ${st}), so it can't be audited right now.`, 502);
  const raw = [];
  stage(2); raw.push(...await checkHttps(ctx)); const tls = await checkTls(ctx); raw.push(...tls.findings);
  stage(3); raw.push(...checkHeaders(ctx)); const tech = checkTechnology(ctx); raw.push(...tech.findings);
  stage(4); raw.push(...checkCookies(ctx));
  stage(5); const meta = await checkMetadata(ctx); raw.push(...meta.findings);
  stage(6); const vulnerabilities = generateVulnerabilities(raw), scoring = calculateScore(vulnerabilities);
  return { target: ctx.target.url.href, scannedAt: new Date().toISOString(), ...scoring, vulnerabilities,
    metadata: { finalUrl: ctx.finalUrl.href, httpStatus: st, httpsAvailable: ctx.httpsAvailable, httpRedirectsToHttps: !!ctx.httpRedirects, tls: tls.info, technologies: tech.technologies, ...meta.metadata } };
}
function runAudit(input, onProgress = () => {}) {
  let t; const cap = new Promise((_, rej) => { t = setTimeout(() => rej(new AuditError('TIMEOUT', 'The audit took too long and was stopped.', 504)), cfg.totalTimeoutMs); });
  return Promise.race([execute(input, onProgress), cap]).finally(() => clearTimeout(t));
}
module.exports = { runAudit, STAGES };
