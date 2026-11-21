const fs = require('fs');

const SEVERITY_RANK = { LOW: 1, MEDIUM: 2, HIGH: 3 };
const ANSI = { HIGH: '\x1b[31m', MEDIUM: '\x1b[33m', LOW: '\x1b[34m', RESET: '\x1b[0m' };

function filterBySeverity(alerts, minSeverity = 'LOW') {
  const minRank = SEVERITY_RANK[minSeverity.toUpperCase()] || 1;
  return alerts.filter(a => (SEVERITY_RANK[a.severity] || 0) >= minRank);
}

function writeAlertsJsonl(filePath, alerts) {
  if (!alerts.length) return;
  const lines = alerts.map(a => JSON.stringify(a)).join('\n') + '\n';
  fs.appendFileSync(filePath, lines, 'utf8');
}

function formatAlertConsole(alert) {
  const color = ANSI[alert.severity] || '';
  return `${color}[${alert.severity}]${ANSI.RESET} ${alert.timestamp} | ${alert.signature_name} | ${alert.src_ip} -> ${alert.dst_ip} | ${alert.details}`;
}

module.exports = { filterBySeverity, writeAlertsJsonl, formatAlertConsole };
