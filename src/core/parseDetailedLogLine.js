const {
  SYSLOG_REGEX,
  INVALID_USER_PATTERN,
  FAILED_LOGIN_PATTERN,
  ACCEPTED_LOGIN_PATTERN,
  NEW_SESSION_PATTERN
} = require('./patterns');
const { formatProto } = require('./helpers/formatProto');

/**
 * Детальный разбор одной строки лога на поля.
 * Строка, не похожая на syslog, не вызывает ошибку: поля остаются "—", opStatus = INFO.
 */
function parseDetailedLogLine(rawLine, lineNumber, fileName) {
  const m = SYSLOG_REGEX.exec(rawLine);

  let month = '—', day = '—', time = '—', host = '—', service = '—', pid = '—', msg = rawLine;
  if (m) {
    month = m[1];
    day = m[2];
    time = m[3];
    host = m[4];
    service = m[5].trim();
    pid = m[6] || '—';
    msg = m[7];
  }

  let opStatus = 'INFO';
  let user = '—';
  let ip = '—';
  let port = '—';
  let details = msg;
  let isFailure = false;
  let isSuccess = false;

  const invM = INVALID_USER_PATTERN.exec(msg);
  const failM = FAILED_LOGIN_PATTERN.exec(msg);
  const accM = ACCEPTED_LOGIN_PATTERN.exec(msg);
  const sessM = NEW_SESSION_PATTERN.exec(msg);

  if (invM) {
    opStatus = 'Invalid';
    user = invM[1];
    ip = invM[2];
    port = invM[3] || '—';
    details = 'Несуществующий пользователь' + formatProto(invM[4]);
    isFailure = true;
  } else if (failM) {
    opStatus = 'Failed';
    user = failM[1];
    ip = failM[2];
    port = failM[3] || '—';
    details = 'Неверный пароль' + formatProto(failM[4]);
    isFailure = true;
  } else if (accM) {
    opStatus = 'Accepted';
    user = accM[1];
    ip = accM[2];
    port = accM[3] || '—';
    details = 'Успешный вход по паролю' + formatProto(accM[4]);
    isSuccess = true;
  } else if (sessM) {
    opStatus = 'Session';
    user = sessM[2];
    details = 'Открытие сессии №' + sessM[1];
  }

  return {
    lineNum: lineNumber,
    fileName,
    month,
    day,
    time,
    host,
    service,
    pid,
    opStatus,
    user,
    ip,
    port,
    details,
    isFailure,
    isSuccess,
    raw: rawLine,
    ts: null
  };
}

module.exports = { parseDetailedLogLine };
