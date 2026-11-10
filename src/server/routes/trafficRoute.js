const { scanPcapDirectory } = require('../../core/pcap/scanPcapDirectory');
const { sendJson } = require('../utils/sendJson');

/** GET /api/traffic — результат анализа всех .pcap из папки pcaps/ */
function handleTrafficRoute(req, res) {
  sendJson(res, 200, scanPcapDirectory());
}

module.exports = { handleTrafficRoute };
