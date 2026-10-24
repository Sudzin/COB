const fs = require('fs');
const path = require('path');
const { LOGS_DIR, LOG_EXTENSIONS } = require('../config');
const { readLogFileSafely } = require('./readLogFileSafely');
const { analyzeLog } = require('./analyzeLog');

/**
 * Сканирует папку logs/, читает и анализирует каждый .txt/.log файл.
 * Битый файл не останавливает работу: он попадает в список со статусом CORRUPTED.
 */
function scanLogsDirectory() {
  if (!fs.existsSync(LOGS_DIR)) {
    return { status: 'DIR_NOT_FOUND', error: 'Папка "logs" не найдена рядом со скриптом.', files: [] };
  }

  const entries = fs.readdirSync(LOGS_DIR);
  const logFiles = entries.filter(f => LOG_EXTENSIONS.includes(path.extname(f).toLowerCase()));

  if (logFiles.length === 0) {
    return { status: 'DIR_EMPTY', error: 'Папка "logs" пуста или не содержит файлов .txt/.log.', files: [] };
  }

  logFiles.sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }));

  const files = [];
  for (const fileName of logFiles) {
    const read = readLogFileSafely(path.join(LOGS_DIR, fileName));

    if (read.error) {
      files.push({
        fileName,
        status: 'CORRUPTED',
        error: read.message,
        totalLines: 0,
        rows: [],
        minTime: null,
        maxTime: null,
        totalDurationSec: 0,
        totalDurationMin: 0
      });
    } else {
      const an = analyzeLog(read.content, fileName);
      files.push({
        fileName,
        status: 'OK',
        totalLines: an.totalLines,
        rows: an.rows,
        minTime: an.minTime,
        maxTime: an.maxTime,
        totalDurationSec: an.totalDurationSec,
        totalDurationMin: an.totalDurationMin
      });
    }
  }

  return { status: 'SUCCESS', files };
}

module.exports = { scanLogsDirectory };
