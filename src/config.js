const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '..');

module.exports = {
  ROOT_DIR,
  PORT: Number(process.env.PORT) || 3000,
  // Папку с логами можно переопределить: LOGS_DIR=D:\my_logs npm start
  LOGS_DIR: process.env.LOGS_DIR ? path.resolve(process.env.LOGS_DIR) : path.join(ROOT_DIR, 'logs'),
  PUBLIC_DIR: path.join(ROOT_DIR, 'public'),
  // ЛР №2: папка с захваченным трафиком (.pcap)
  PCAPS_DIR: process.env.PCAPS_DIR ? path.resolve(process.env.PCAPS_DIR) : path.join(ROOT_DIR, 'pcaps'),
  PCAP_EXTENSIONS: ['.pcap'],
  PCAP_MAX_BYTES: 200 * 1024 * 1024,
  // В формате syslog нет года, поэтому он задан здесь
  LOG_YEAR: 2026,
  LOG_EXTENSIONS: ['.txt', '.log'],

  // Пороги анализа трафика (ЛР №2)
  TRAFFIC: {
    MIN_DURATION_SEC: 0.001,   // короче — PPS/BPS не считаем (деление на ~0 даёт мусор)
    SCAN_MIN_PORTS: 10,        // сканирование: столько разных портов одного узла от одного источника
    SCAN_MAX_PKTS_PER_PORT: 2, // ...при этом на порт приходится не больше N пакетов (SYN + RST)
    FLOOD_MIN_SOURCES: 10,     // SYN-флуд: SYN без ACK на один порт от стольких источников...
    FLOOD_MIN_PACKETS: 100,    // ...или столько SYN без ACK даже от одного источника
    ICMP_BIG_SIZE: 1000,       // ICMP-пакет крупнее (байт) считается аномальным
    ICMP_FLOOD_PACKETS: 20,    // ICMP-флуд: минимум пакетов в потоке...
    ICMP_FLOOD_PPS: 100,       // ...и частота (пакетов/с)
    ICMP_NORMAL_TYPES: [0, 3, 8, 11], // echo reply, unreachable, echo request, time exceeded
    MAX_POINTS: 20000,         // максимум точек для графиков в ответе API
    MAX_FLOWS: 2000            // максимум потоков в ответе API
  }
};
