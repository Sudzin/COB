#!/usr/bin/env node
/**
 * Живой захват трафика для ЛР №2: запускает dumpcap (идёт с Wireshark/Npcap) или tcpdump
 * и сохраняет .pcap в папку pcaps/, откуда его подхватит анализатор.
 *
 *   npm run capture -- --list
 *   npm run capture -- --iface "Ethernet 5" --count 500
 *   npm run capture -- --iface 4 --time 30 --out pcaps/ping.pcap
 */
const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { PCAPS_DIR } = require('../src/config');

function parseArgs(argv) {
  const opts = { count: 500 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const val = () => argv[++i];
    if (a === '--iface' || a === '-i') opts.iface = val();
    else if (a === '--count' || a === '-c') opts.count = Number(val());
    else if (a === '--time' || a === '-t') opts.time = Number(val());
    else if (a === '--out' || a === '-o') opts.out = val();
    else if (a === '--dumpcap') opts.dumpcap = val();
    else if (a === '--list' || a === '-D') opts.list = true;
    else if (a === '--help' || a === '-h') opts.help = true;
    else { console.error('Неизвестный аргумент: ' + a); process.exit(2); }
  }
  return opts;
}

function works(cmd, args) {
  try { return spawnSync(cmd, args, { stdio: 'ignore' }).status === 0; } catch (e) { return false; }
}

function findCapturer(custom) {
  const candidates = [custom, process.env.DUMPCAP, 'dumpcap',
    'C:\\Program Files\\Wireshark\\dumpcap.exe', 'C:\\Program Files (x86)\\Wireshark\\dumpcap.exe'].filter(Boolean);
  for (const c of candidates) if (works(c, ['-v'])) return { tool: 'dumpcap', cmd: c };
  if (process.platform !== 'win32' && works('tcpdump', ['--version'])) return { tool: 'tcpdump', cmd: 'tcpdump' };
  return null;
}

const opts = parseArgs(process.argv.slice(2));

if (opts.help) {
  console.log('Использование: npm run capture -- [--list] --iface <имя|номер> [--count 500] [--time секунды] [--out файл.pcap]');
  process.exit(0);
}

const cap = findCapturer(opts.dumpcap);
if (!cap) {
  console.error('Не найден dumpcap. Установите Wireshark (вместе с Npcap) или укажите путь: --dumpcap "C:\\...\\dumpcap.exe"');
  process.exit(1);
}

if (opts.list) {
  process.exit(spawnSync(cap.cmd, ['-D'], { stdio: 'inherit' }).status || 0);
}

if (!opts.iface) {
  console.error('Не указан интерфейс. Список: npm run capture -- --list');
  process.exit(2);
}
if (!Number.isInteger(opts.count) || opts.count <= 0) {
  console.error('--count должен быть положительным целым числом');
  process.exit(2);
}

const stamp = new Date().toISOString().replace(/[:T]/g, '-').slice(0, 19);
const out = path.resolve(opts.out || path.join(PCAPS_DIR, 'capture_' + stamp + '.pcap'));
fs.mkdirSync(path.dirname(out), { recursive: true });

const args = cap.tool === 'dumpcap'
  ? ['-i', opts.iface, '-c', String(opts.count), '-F', 'pcap', '-w', out]
  : ['-i', opts.iface, '-c', String(opts.count), '-w', out];
if (opts.time && cap.tool === 'dumpcap') args.push('-a', 'duration:' + opts.time);
if (opts.time && cap.tool !== 'dumpcap') console.warn('[!] --time поддерживается только dumpcap; захват остановится по --count или Ctrl+C.');

console.log('[*] Захват: ' + cap.tool + ' → ' + out + ' (интерфейс: ' + opts.iface + ', пакетов: до ' + opts.count + (opts.time ? ', не дольше ' + opts.time + ' с' : '') + ')');
console.log('[*] Нужны права на захват (Npcap / администратор). Остановка — Ctrl+C.');

const child = spawn(cap.cmd, args, { stdio: 'inherit' });
child.on('error', e => { console.error('Не удалось запустить ' + cap.cmd + ': ' + e.message); process.exit(1); });
child.on('exit', code => {
  if (code === 0 && fs.existsSync(out)) console.log('[*] Готово: ' + out + '\n    Откройте http://localhost:3000 → вкладка «Трафик».');
  else console.error('[!] Захват завершился с кодом ' + code);
  process.exit(code || 0);
});
