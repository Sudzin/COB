const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

// Папка с логами задаётся ДО подключения модулей (config читает LOGS_DIR при загрузке)
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'log-analyzer-'));
process.env.LOGS_DIR = tmpDir;
const { scanLogsDirectory } = require('../src/core/scanLogsDirectory');

test.after(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

test('пустая папка → DIR_EMPTY', () => {
  assert.strictEqual(scanLogsDirectory().status, 'DIR_EMPTY');
});

test('нормальный, пустой и битый файлы обрабатываются вместе', () => {
  fs.writeFileSync(path.join(tmpDir, 'a.txt'), [
    'Oct 13 11:00:00 srv sshd[1]: Failed password for root from 203.0.113.45 port 22 ssh2',
    'Oct 13 11:10:00 srv sshd[1]: Failed password for root from 203.0.113.45 port 22 ssh2',
    'мусорная строка'
  ].join('\n'));
  fs.writeFileSync(path.join(tmpDir, 'b.txt'), '');
  fs.writeFileSync(path.join(tmpDir, 'c.log'), Buffer.from([0xff, 0xfe, 0xfa]));
  fs.writeFileSync(path.join(tmpDir, 'ignored.md'), 'не лог');

  const res = scanLogsDirectory();
  assert.strictEqual(res.status, 'SUCCESS');
  assert.deepStrictEqual(res.files.map(f => f.fileName), ['a.txt', 'b.txt', 'c.log']);

  const [a, b, c] = res.files;
  assert.strictEqual(a.status, 'OK');
  assert.strictEqual(a.totalLines, 3);
  assert.strictEqual(a.totalDurationMin, 10);
  assert.strictEqual(b.status, 'CORRUPTED');
  assert.match(b.error, /пуст/);
  assert.strictEqual(c.status, 'CORRUPTED');
  assert.match(c.error, /кодировк/);
});
