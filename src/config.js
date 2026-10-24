const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '..');

module.exports = {
  ROOT_DIR,
  PORT: Number(process.env.PORT) || 3000,
  // Папку с логами можно переопределить: LOGS_DIR=D:\my_logs npm start
  LOGS_DIR: process.env.LOGS_DIR ? path.resolve(process.env.LOGS_DIR) : path.join(ROOT_DIR, 'logs'),
  PUBLIC_DIR: path.join(ROOT_DIR, 'public'),
  // В формате syslog нет года, поэтому он задан здесь
  LOG_YEAR: 2026,
  LOG_EXTENSIONS: ['.txt', '.log']
};
