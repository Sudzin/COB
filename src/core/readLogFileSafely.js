const fs = require('fs');

/**
 * Читает файл лога и не падает на типовых проблемах.
 * @returns {{content: string, size: number} | {error: string, message: string}}
 */
function readLogFileSafely(filePath) {
  if (!fs.existsSync(filePath)) {
    return { error: 'ERR_NOT_FOUND', message: 'Файл не найден' };
  }
  const stat = fs.statSync(filePath);
  if (stat.size === 0) {
    return { error: 'ERR_EMPTY', message: 'Файл пуст (0 байт)' };
  }
  try {
    const buffer = fs.readFileSync(filePath);
    const decoder = new TextDecoder('utf-8', { fatal: true });
    return { content: decoder.decode(buffer), size: stat.size };
  } catch (err) {
    return { error: 'ERR_ENCODING', message: 'Ошибка кодировки (не UTF-8)' };
  }
}

module.exports = { readLogFileSafely };
