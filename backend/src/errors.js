// AuditError carries a user-safe message. Raw network errors are mapped here and never sent to clients.
class AuditError extends Error {
  constructor(code, message, status = 400) { super(message); this.code = code; this.status = status; }
}
const CERT = /^(CERT_|DEPTH_ZERO|SELF_SIGNED|UNABLE_TO_|ERR_TLS|ERR_SSL|HOSTNAME_MISMATCH|ERR_OSSL)/;
const isCert = c => CERT.test(String(c || ''));
function mapNetError(e) {
  if (e instanceof AuditError) return e;
  const c = e && e.code;
  if (c === 'ENOTFOUND' || c === 'EAI_AGAIN') return new AuditError('DNS_FAILURE', "We couldn't resolve that domain. Check the spelling and that its DNS records exist.", 502);
  if (c === 'AUDIT_TIMEOUT' || c === 'ETIMEDOUT') return new AuditError('TIMEOUT', 'The website took too long to respond.', 504);
  if (['ECONNREFUSED', 'ECONNRESET', 'EHOSTUNREACH', 'ENETUNREACH', 'EPIPE'].includes(c)) return new AuditError('UNREACHABLE', "We couldn't connect to that website. Is it online and publicly reachable?", 502);
  if (isCert(c)) return new AuditError('SSL_ERROR', "The website's SSL/TLS certificate could not be verified or negotiated.", 502);
  if (c === 'TOO_MANY_REDIRECTS') return new AuditError('UNREACHABLE', 'The website redirected too many times.', 502);
  return new AuditError('UNEXPECTED', 'Something unexpected happened while auditing that website.', 500);
}
module.exports = { AuditError, mapNetError, isCert };
