// calculateScore: severity-weighted score (100 = nothing found), risk level, summary counts and category status.
const W = { critical: 25, high: 12, medium: 6, low: 2, info: 0 };
const CATS = ['HTTP Security', 'Security Headers', 'Cookies', 'Secrets', 'APIs', 'Cloud Configuration', 'Client-Side Security'];
function calculateScore(vulns) {
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let penalty = 0; for (const v of vulns) { summary[v.severity]++; penalty += W[v.severity]; }
  const score = Math.max(0, 100 - penalty);
  const riskLevel = score >= 90 ? 'Low' : score >= 70 ? 'Medium' : score >= 45 ? 'High' : 'Critical';
  const categories = CATS.map(name => {
    const own = vulns.filter(v => v.category === name && v.severity !== 'info');
    const status = own.some(v => ['critical', 'high'].includes(v.severity)) ? 'fail' : own.length ? 'warn' : 'pass';
    return { name, status, issues: own.length };
  });
  return { score, riskLevel, summary, categories };
}
module.exports = { calculateScore, W };
