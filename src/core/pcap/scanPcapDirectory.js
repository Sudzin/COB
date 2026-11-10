const fs = require('fs');
const path = require('path');
const { PCAPS_DIR, PCAP_EXTENSIONS, PCAP_MAX_BYTES, TRAFFIC } = require('../../config');
const { analyzePcap } = require('./analyzePcap');

/**
 * Сканирует папку pcaps/ и анализирует каждый .pcap. Битый файл не останавливает работу:
 * он попадает в список со статусом CORRUPTED.
 */
function scanPcapDirectory() {
  if (!fs.existsSync(PCAPS_DIR)) {
    return { status: 'DIR_NOT_FOUND', error: 'Папка "pcaps" не найдена рядом со скриптом.', files: [] };
  }

  const names = fs.readdirSync(PCAPS_DIR)
    .filter(f => PCAP_EXTENSIONS.includes(path.extname(f).toLowerCase()))
    .sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }));

  if (names.length === 0) {
    return { status: 'DIR_EMPTY', error: 'В папке "pcaps" нет файлов .pcap. Положите захваченный трафик или запустите npm run capture.', files: [] };
  }

  const files = names.map(fileName => {
    try {
      const filePath = path.join(PCAPS_DIR, fileName);
      const size = fs.statSync(filePath).size;
      if (size === 0) throw new Error('Файл пуст (0 байт)');
      if (size > PCAP_MAX_BYTES) throw new Error('Файл слишком большой (больше ' + PCAP_MAX_BYTES / 1048576 + ' МБ)');
      return analyzePcap(fs.readFileSync(filePath), fileName, TRAFFIC);
    } catch (err) {
      return { fileName, status: 'CORRUPTED', error: err.message };
    }
  });

  return { status: 'SUCCESS', files };
}

module.exports = { scanPcapDirectory };
