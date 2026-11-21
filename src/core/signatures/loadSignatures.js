const fs = require('fs');
const path = require('path');

/**
 * Загружает активные сигнатуры из JSON-файла или всех .json в каталоге.
 * @param {string} targetPath путь к папке signatures/ или конкретному .json
 * @returns {Array<object>}
 */
function loadSignatures(targetPath) {
  const stat = fs.statSync(targetPath);
  const files = stat.isDirectory()
    ? fs.readdirSync(targetPath)
        .filter(f => f.endsWith('.json'))
        .sort()
        .map(f => path.join(targetPath, f))
    : [targetPath];

  const rules = [];
  for (const file of files) {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!Array.isArray(parsed)) {
      throw new Error(`Файл сигнатур должен содержать JSON-массив: ${file}`);
    }
    for (const sig of parsed) {
      if (sig.enabled === false) continue;
      rules.push(sig);
    }
  }
  return rules;
}

module.exports = { loadSignatures };
