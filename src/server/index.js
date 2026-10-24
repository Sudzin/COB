/**
 * Точка входа. Запуск: npm start  (или node src/server/index.js)
 */
const { PORT } = require('../config');
const { createServer } = require('./createServer');

createServer().listen(PORT, () => {
  console.log(`[✓] СЕРВЕР ЗАПУЩЕН: http://localhost:${PORT}`);
});
