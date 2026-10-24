/**
 * Все регулярные выражения проекта в одном месте.
 * Названия FAILED_LOGIN_PATTERN / INVALID_USER_PATTERN совпадают с заданием ЛР №1.
 */

// Базовая структура строки syslog: "Oct 13 11:09:50 host sshd[123]: сообщение"
const SYSLOG_REGEX = /^([A-Z][a-z]{2})\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:\[]+)(?:\[(\d+)\])?:\s+(.*)$/;

const IP = '(\\d{1,3}(?:\\.\\d{1,3}){3})';

const INVALID_USER_PATTERN = new RegExp('Invalid user (\\S+) from ' + IP + '(?: port (\\d+))?(.*)', 'i');
const FAILED_LOGIN_PATTERN = new RegExp('Failed password for (?:invalid user )?(\\S+) from ' + IP + '(?: port (\\d+))?(.*)', 'i');
const ACCEPTED_LOGIN_PATTERN = new RegExp('Accepted password for (\\S+) from ' + IP + '(?: port (\\d+))?(.*)', 'i');

// Имя пользователя без завершающей точки ("... of user root.")
const NEW_SESSION_PATTERN = /New session (\d+) of user (\S+?)\.?\s*$/i;

module.exports = {
  SYSLOG_REGEX,
  INVALID_USER_PATTERN,
  FAILED_LOGIN_PATTERN,
  ACCEPTED_LOGIN_PATTERN,
  NEW_SESSION_PATTERN
};
