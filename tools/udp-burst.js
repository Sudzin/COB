#!/usr/bin/env node
/**
 * Генератор «высокой частоты» для ЛР №2 (п. 8): шлёт пустые UDP-пакеты в цикле.
 * Безопасность: адресат — только localhost или частная сеть, число пакетов и частота ограничены.
 *
 *   npm run udp-burst -- --host 127.0.0.1 --port 9999 --count 5000 --rate 2000
 */
const dgram = require('dgram');

const MAX_COUNT = 100000;
const MAX_RATE = 20000;

const opts = { host: '127.0.0.1', port: 9999, count: 5000, rate: 2000 };
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i++) {
  const key = argv[i].replace(/^--/, '');
  if (!(key in opts)) { console.error('Неизвестный аргумент: ' + argv[i]); process.exit(2); }
  opts[key] = key === 'host' ? argv[++i] : Number(argv[++i]);
}
if (opts.host === 'localhost') opts.host = '127.0.0.1';

function isPrivateIPv4(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

if (!isPrivateIPv4(opts.host)) {
  console.error('Отказ: отправка разрешена только на localhost и адреса частной сети (10.*, 172.16–31.*, 192.168.*, 127.*).');
  process.exit(1);
}
if (!Number.isInteger(opts.port) || opts.port < 1 || opts.port > 65535) { console.error('Некорректный --port'); process.exit(2); }
if (!Number.isInteger(opts.count) || opts.count < 1 || opts.count > MAX_COUNT) { console.error('--count: от 1 до ' + MAX_COUNT); process.exit(2); }
if (!Number.isInteger(opts.rate) || opts.rate < 1 || opts.rate > MAX_RATE) { console.error('--rate: от 1 до ' + MAX_RATE + ' пакетов/с'); process.exit(2); }

const socket = dgram.createSocket('udp4');
socket.on('error', () => {}); // ответы ICMP «порт недоступен» нам не важны

const EMPTY = Buffer.alloc(0);
const TICK_MS = 10;
const perTick = Math.max(1, Math.round(opts.rate * TICK_MS / 1000));
let sent = 0;
const startedAt = Date.now();

console.log('[*] Отправка ' + opts.count + ' пустых UDP-пакетов на ' + opts.host + ':' + opts.port + ' (~' + opts.rate + ' пакетов/с)');

const timer = setInterval(() => {
  for (let i = 0; i < perTick && sent < opts.count; i++, sent++) socket.send(EMPTY, opts.port, opts.host);
  if (sent >= opts.count) {
    clearInterval(timer);
    setTimeout(() => {
      socket.close();
      const sec = (Date.now() - startedAt) / 1000;
      console.log('[*] Готово: ' + sent + ' пакетов за ' + sec.toFixed(2) + ' с (' + Math.round(sent / sec) + ' пакетов/с)');
    }, 200);
  }
}, TICK_MS);
