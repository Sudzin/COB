const { parseDetailedLogLine } = require('./parseDetailedLogLine');
const { LOG_YEAR } = require('../config');

/**
 * Разбирает текст лога целиком: строки, временные метки, длительность записи.
 */
function analyzeLog(content, fileName) {
  const rawLines = content.split(/\r?\n/).filter(l => l.trim().length > 0);
  const rows = rawLines.map((l, idx) => parseDetailedLogLine(l, idx + 1, fileName));

  let minTime = null;
  let maxTime = null;

  rows.forEach(r => {
    if (r.time !== '—' && r.month !== '—') {
      const d = new Date(`${r.month} ${r.day} ${r.time} ${LOG_YEAR}`);
      if (!isNaN(d.getTime())) {
        r.ts = d.getTime();
        if (!minTime || d < minTime) minTime = d;
        if (!maxTime || d > maxTime) maxTime = d;
      }
    }
  });

  let totalDurationSec = 0;
  if (minTime && maxTime) {
    totalDurationSec = Math.max(0, Math.round((maxTime - minTime) / 1000));
  }
  const totalDurationMin = Math.ceil(totalDurationSec / 60) || 1;

  return {
    fileName,
    totalLines: rawLines.length,
    rows,
    minTime: minTime ? minTime.toISOString() : null,
    maxTime: maxTime ? maxTime.toISOString() : null,
    totalDurationSec,
    totalDurationMin
  };
}

module.exports = { analyzeLog };
