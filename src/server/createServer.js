const http = require('http');
const { handleScanRoute } = require('./routes/scanRoute');
const { handleStaticRoute } = require('./routes/staticRoute');
const { sendText } = require('./utils/sendText');

/** Собирает HTTP-сервер: /api/* — данные, всё остальное — статика из public/. */
function createServer() {
  return http.createServer((req, res) => {
    if (req.method !== 'GET') {
      res.setHeader('Allow', 'GET');
      return sendText(res, 405, 'Method not allowed');
    }

    const url = new URL(req.url, 'http://localhost');

    if (url.pathname === '/api/scan') return handleScanRoute(req, res);
    return handleStaticRoute(url.pathname, res);
  });
}

module.exports = { createServer };
