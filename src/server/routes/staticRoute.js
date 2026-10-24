const fs = require('fs');
const path = require('path');
const { PUBLIC_DIR } = require('../../config');
const { getMimeType } = require('../utils/getMimeType');
const { sendText } = require('../utils/sendText');

/** Отдаёт файлы из public/. Выйти за пределы этой папки (../) нельзя. */
function handleStaticRoute(pathname, res) {
  let relPath;
  try {
    relPath = decodeURIComponent(pathname);
  } catch (e) {
    return sendText(res, 400, 'Bad request');
  }
  if (relPath.includes('\0')) return sendText(res, 400, 'Bad request');
  if (relPath === '/') relPath = '/index.html';

  const filePath = path.join(PUBLIC_DIR, relPath);
  if (!filePath.startsWith(PUBLIC_DIR + path.sep)) {
    return sendText(res, 403, 'Forbidden');
  }

  fs.readFile(filePath, (err, data) => {
    if (err) return sendText(res, 404, 'Not found');
    res.writeHead(200, { 'Content-Type': getMimeType(filePath) });
    res.end(data);
  });
}

module.exports = { handleStaticRoute };
