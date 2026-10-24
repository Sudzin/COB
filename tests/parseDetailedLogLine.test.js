const test = require('node:test');
const assert = require('node:assert');
const { parseDetailedLogLine } = require('../src/core/parseDetailedLogLine');

const parse = line => parseDetailedLogLine(line, 1, 'test.txt');

test('Failed password: неверный пароль', () => {
  const r = parse('Oct 13 11:09:50 srv sshd[1234]: Failed password for root from 203.0.113.45 port 22 ssh2');
  assert.strictEqual(r.opStatus, 'Failed');
  assert.strictEqual(r.user, 'root');
  assert.strictEqual(r.ip, '203.0.113.45');
  assert.strictEqual(r.port, '22');
  assert.strictEqual(r.service, 'sshd');
  assert.strictEqual(r.pid, '1234');
  assert.strictEqual(r.details, 'Неверный пароль · ssh2');
  assert.strictEqual(r.isFailure, true);
});

test('Invalid user: несуществующий пользователь', () => {
  const r = parse('Oct 13 11:09:51 srv sshd[1234]: Invalid user admin from 192.0.2.1 port 4000');
  assert.strictEqual(r.opStatus, 'Invalid');
  assert.strictEqual(r.user, 'admin');
  assert.strictEqual(r.ip, '192.0.2.1');
  assert.strictEqual(r.details, 'Несуществующий пользователь');
  assert.strictEqual(r.isFailure, true);
});

test('Accepted password: успешный вход', () => {
  const r = parse('Oct 13 11:10:00 srv sshd[1235]: Accepted password for bob from 10.0.0.5 port 22 ssh2');
  assert.strictEqual(r.opStatus, 'Accepted');
  assert.strictEqual(r.isSuccess, true);
  assert.strictEqual(r.isFailure, false);
});

test('New session: имя пользователя без точки', () => {
  const r = parse('Oct 13 11:10:01 srv systemd-logind[1]: New session 4 of user bob.');
  assert.strictEqual(r.opStatus, 'Session');
  assert.strictEqual(r.user, 'bob');
  assert.strictEqual(r.details, 'Открытие сессии №4');
});

test('Некорректная строка не вызывает ошибку', () => {
  const r = parse('garbage line');
  assert.strictEqual(r.opStatus, 'INFO');
  assert.strictEqual(r.ip, '—');
  assert.strictEqual(r.isFailure, false);
  assert.strictEqual(r.raw, 'garbage line');
});
