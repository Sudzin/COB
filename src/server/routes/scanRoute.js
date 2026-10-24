const { scanLogsDirectory } = require('../../core/scanLogsDirectory');
const { sendJson } = require('../utils/sendJson');

/** GET /api/scan — результат анализа всех файлов из папки logs/ */
function handleScanRoute(req, res) {
  sendJson(res, 200, scanLogsDirectory());
}

module.exports = { handleScanRoute };
