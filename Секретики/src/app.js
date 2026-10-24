/**
 * Лабораторная работа №1 // Выявление аномалий и инцидентов ИБ в системных журналах
 * Запуск: node app.js
 */

const fs = require('fs');
const path = require('path');
const http = require('http');

const LOGS_DIR = path.resolve(__dirname, 'logs');
const PORT = 3000;

// Парсинг базовой структуры Syslog
const SYSLOG_REGEX = /^([A-Z][a-z]{2})\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:\[]+)(?:\[(\d+)\])?:\s+(.*)$/;

function readLogFileSafely(filePath) {
  if (!fs.existsSync(filePath)) {
    return { error: 'ERR_NOT_FOUND', message: 'Файл не найден' };
  }
  const stat = fs.statSync(filePath);
  if (stat.size === 0) {
    return { error: 'ERR_EMPTY', message: 'Файл пуст (0 байт)' };
  }
  try {
    const buffer = fs.readFileSync(filePath);
    const decoder = new TextDecoder('utf-8', { fatal: true });
    return { content: decoder.decode(buffer), size: stat.size };
  } catch (err) {
    return { error: 'ERR_ENCODING', message: 'Ошибка кодировки (не UTF-8)' };
  }
}

/**
 * Детальный разбор полей строки лога
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

  const IP = '(\\d{1,3}(?:\\.\\d{1,3}){3})';
  const invM = new RegExp('Invalid user (\\S+) from ' + IP + '(?: port (\\d+))?(.*)', 'i').exec(msg);
  const failM = new RegExp('Failed password for (?:invalid user )?(\\S+) from ' + IP + '(?: port (\\d+))?(.*)', 'i').exec(msg);
  const accM = new RegExp('Accepted password for (\\S+) from ' + IP + '(?: port (\\d+))?(.*)', 'i').exec(msg);
  // имя пользователя без завершающей точки ("... of user root.")
  const sessM = /New session (\d+) of user (\S+?)\.?\s*$/i.exec(msg);

  const proto = rest => (rest && rest.trim() ? ' · ' + rest.trim() : '');

  if (invM) {
    opStatus = 'Invalid';
    user = invM[1];
    ip = invM[2];
    port = invM[3] || '—';
    details = 'Несуществующий пользователь' + proto(invM[4]);
    isFailure = true;
  } else if (failM) {
    opStatus = 'Failed';
    user = failM[1];
    ip = failM[2];
    port = failM[3] || '—';
    details = 'Неверный пароль' + proto(failM[4]);
    isFailure = true;
  } else if (accM) {
    opStatus = 'Accepted';
    user = accM[1];
    ip = accM[2];
    port = accM[3] || '—';
    details = 'Успешный вход по паролю' + proto(accM[4]);
    isSuccess = true;
  } else if (sessM) {
    opStatus = 'Session';
    user = sessM[2];
    details = 'Открытие сессии №' + sessM[1];
  }

  return {
    lineNum: lineNumber,
    fileName: fileName,
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

function analyzeLog(content, fileName) {
  const rawLines = content.split(/\r?\n/).filter(l => l.trim().length > 0);
  const rows = rawLines.map((l, idx) => parseDetailedLogLine(l, idx + 1, fileName));

  let minTime = null;
  let maxTime = null;

  rows.forEach(r => {
    if (r.time !== '—' && r.month !== '—') {
      const d = new Date(`${r.month} ${r.day} ${r.time} 2026`);
      if (!isNaN(d.getTime())) {
        r.ts = d.getTime();
        if (!minTime || d < minTime) minTime = d;
        if (!maxTime || d > maxTime) maxTime = d;
      }
    }
  });

  let totalDurationSec = 0;
  if (minTime && maxTime) {
    totalDurationSec = Math.max(0, Math.round((maxTime - minTime) / 1000));
  }
  const totalDurationMin = Math.ceil(totalDurationSec / 60) || 1;

  return {
    fileName,
    totalLines: rawLines.length,
    rows,
    minTime: minTime ? minTime.toISOString() : null,
    maxTime: maxTime ? maxTime.toISOString() : null,
    totalDurationSec,
    totalDurationMin
  };
}

function scanLogsDirectory() {
  if (!fs.existsSync(LOGS_DIR)) {
    return { status: 'DIR_NOT_FOUND', error: 'Папка "logs" не найдена рядом со скриптом.', files: [] };
  }

  const entries = fs.readdirSync(LOGS_DIR);
  const logFiles = entries.filter(f => f.toLowerCase().endsWith('.txt') || f.toLowerCase().endsWith('.log'));

  if (logFiles.length === 0) {
    return { status: 'DIR_EMPTY', error: 'Папка "logs" пуста или не содержит файлов .txt/.log.', files: [] };
  }

  logFiles.sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }));

  const files = [];
  for (const fileName of logFiles) {
    const fullPath = path.join(LOGS_DIR, fileName);
    const read = readLogFileSafely(fullPath);

    if (read.error) {
      files.push({
        fileName,
        status: 'CORRUPTED',
        error: read.message,
        totalLines: 0,
        rows: [],
        minTime: null,
        maxTime: null,
        totalDurationSec: 0,
        totalDurationMin: 0
      });
    } else {
      const an = analyzeLog(read.content, fileName);
      files.push({
        fileName,
        status: 'OK',
        totalLines: an.totalLines,
        rows: an.rows,
        minTime: an.minTime,
        maxTime: an.maxTime,
        totalDurationSec: an.totalDurationSec,
        totalDurationMin: an.totalDurationMin
      });
    }
  }

  return { status: 'SUCCESS', files };
}

/* ------------------------------------------------------------------ *
 *  ФРОНТЕНД
 *  Внимание: внутри PAGE нельзя использовать обратные кавычки и ${...},
 *  поэтому клиентский код написан на конкатенации строк.
 * ------------------------------------------------------------------ */
const PAGE = String.raw`<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ЖУРНАЛ ИБ // АНАЛИЗАТОР</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&family=Source+Serif+4:wght@600;700&display=swap" rel="stylesheet">
<style>
:root{
  --paper:#e6e4df;
  --paper-2:#dad7cf;
  --paper-3:#efede9;
  --ink:#1a1c18;
  --copper:#c85a28;
  --copper-deep:#9e3e14;
  --copper-hi:#e06a34;
  --teal:#3f6168;
  --teal-hi:#8fb5bd;
  --muted:#575952;
  --danger:#ab1f1f;

  /* Шрифты: Anthropic Serif / Sans / Mono, если установлены; иначе близкие аналоги */
  --f-serif:'Anthropic Serif','Tiempos Headline','Source Serif 4','Charter','Iowan Old Style','Palatino Linotype',Georgia,serif;
  --f-sans:'Anthropic Sans','Styrene B','Inter',system-ui,-apple-system,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;
  --f-mono:'Anthropic Mono','JetBrains Mono','SF Mono','Cascadia Mono',Menlo,Consolas,'Liberation Mono',monospace;
}

*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
button,input,select{font-family:var(--f-sans);}
body{
  background-color:var(--paper);
  background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='160' height='160'><filter id='n'><feTurbulence type='fractalNoise' baseFrequency='.8' numOctaves='2' stitchTiles='stitch'/><feColorMatrix values='0 0 0 0 .11 0 0 0 0 .11 0 0 0 0 .11 0 0 0 .06 0'/></filter><rect width='100%' height='100%' filter='url(%23n)'/></svg>");
  color:var(--ink);
  font:400 15px/1.5 var(--f-sans);
  padding-bottom:4rem;
  overflow-x:hidden;
}

/* ШАПКА */
.mast{
  background:var(--ink);
  color:var(--paper);
  padding:.9rem 2vw;
  border-bottom:4px solid var(--copper);
  display:flex;
  align-items:center;
  justify-content:space-between;
  flex-wrap:wrap;
  gap:1rem;
}
.brand{font:700 1.9rem/1 var(--f-serif);letter-spacing:.02em;text-transform:uppercase;}
.brand span{color:var(--copper-hi);}

.nav-cluster{display:flex;align-items:center;gap:.6rem;}
.nav-tab-btn{
  background:transparent;
  border:2px solid rgba(230,228,223,.3);
  color:var(--paper);
  padding:.55rem 1.1rem;
  font:700 .8rem var(--f-sans);
  letter-spacing:.06em;
  text-transform:uppercase;
  cursor:pointer;
  transition:all .12s;
}
.nav-tab-btn:hover{border-color:var(--copper-hi);color:var(--copper-hi);}
.nav-tab-btn.active{background:var(--copper);border-color:var(--copper);color:#fff;box-shadow:3px 3px 0 rgba(0,0,0,.5);}

.status-badge{
  font:700 .75rem var(--f-sans);
  letter-spacing:.08em;
  color:var(--teal-hi);
  text-transform:uppercase;
  border:1px solid rgba(143,181,189,.35);
  padding:.45rem .8rem;
  display:inline-flex;
  align-items:center;
  gap:.4rem;
}

/* СЕТКА */
.app-grid{
  display:grid;
  grid-template-columns:360px minmax(0,1fr);
  gap:2vw;
  padding:1.8rem 2vw;
  width:100%;
}
.app-grid > div{min-width:0;}
@media (max-width:1100px){.app-grid{grid-template-columns:1fr;}}

.panel{background:var(--paper-3);border:3px solid var(--ink);box-shadow:6px 6px 0 var(--ink);padding:1.4rem;margin-bottom:1.8rem;}
.panel--alt{box-shadow:6px 6px 0 var(--copper);}
.panel-head{
  font:700 1.55rem/1.1 var(--f-serif);
  text-transform:uppercase;
  border-bottom:2px solid var(--ink);
  padding-bottom:.6rem;
  margin-bottom:1.1rem;
  display:flex;
  flex-wrap:wrap;
  justify-content:space-between;
  align-items:baseline;
  gap:.3rem 1rem;
}
.panel-head .tag{font:700 .75rem var(--f-sans);letter-spacing:.08em;color:var(--copper-deep);white-space:nowrap;}

/* КАРТОЧКИ ФАЙЛОВ */
.file-list{display:grid;gap:.8rem;}
.file-item{
  background:var(--paper);
  border:2px solid var(--ink);
  box-shadow:4px 4px 0 var(--ink);
  padding:.7rem 1rem;
  cursor:pointer;
  display:flex;
  justify-content:space-between;
  align-items:center;
  gap:.8rem;
  transition:transform .12s,box-shadow .12s,background .12s;
}
.file-item .fname{font:600 .88rem var(--f-mono);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.file-item:hover{background:#fff;transform:translate(-2px,-2px);box-shadow:6px 6px 0 var(--ink);}
.file-item.active{background:var(--ink);color:var(--paper);box-shadow:4px 4px 0 var(--copper);}
.empty{padding:1rem;color:var(--muted);font-size:.9rem;}

.badge{
  font:700 .72rem var(--f-sans);
  letter-spacing:.05em;
  padding:.24rem 0;
  border:2px solid currentColor;
  display:inline-block;
  text-align:center;
  width:108px;
  min-width:108px;
  white-space:nowrap;
}
.badge.alert{color:var(--copper-deep);background:rgba(200,90,40,.08);}
.file-item.active .badge.alert{color:var(--copper-hi);background:transparent;}
.badge.clean{color:var(--teal);background:rgba(63,97,104,.06);}
.file-item.active .badge.clean{color:var(--teal-hi);background:transparent;}
.badge.err{color:var(--danger);}

/* ЕДИНЫЕ ЭЛЕМЕНТЫ УПРАВЛЕНИЯ */
.ctl{
  height:38px;
  padding:0 .7rem;
  border:2px solid var(--ink);
  border-radius:0;
  background:var(--paper);
  color:var(--ink);
  font:600 .86rem/1 var(--f-sans);
  outline:none;
}
.ctl:focus{border-color:var(--copper);background:#fff;}
.ctl::placeholder{color:#8a8c84;font-weight:400;}

.btn-action{
  height:38px;
  padding:0 1.1rem;
  background:var(--copper);
  color:#fff;
  border:2px solid var(--ink);
  font:700 .78rem var(--f-sans);
  letter-spacing:.06em;
  text-transform:uppercase;
  cursor:pointer;
  box-shadow:3px 3px 0 var(--ink);
}
.btn-action:hover{background:var(--copper-hi);}
.btn-pdf{background:var(--ink);color:var(--paper);margin-left:auto;}
.btn-pdf:hover{background:var(--copper-deep);color:#fff;}
.btn-ghost{
  height:32px;
  padding:0 .8rem;
  background:transparent;
  color:var(--ink);
  border:2px solid var(--ink);
  font:700 .7rem var(--f-sans);
  letter-spacing:.06em;
  text-transform:uppercase;
  cursor:pointer;
}
.btn-ghost:hover{background:var(--ink);color:var(--paper);}

/* ПАРАМЕТРЫ */
.filter-deck{
  background:var(--paper-2);
  border:2px solid var(--ink);
  padding:1rem 1.1rem;
  margin-bottom:1.2rem;
  display:grid;
  gap:1rem;
}
.filter-row{display:flex;flex-wrap:wrap;align-items:center;gap:.8rem 1.6rem;}
.param-unit{display:flex;align-items:center;gap:.55rem;white-space:nowrap;}
.param-unit label{font:700 .72rem var(--f-sans);letter-spacing:.07em;color:var(--teal);text-transform:uppercase;}
.hint{font:500 .78rem var(--f-sans);color:var(--muted);}

.seg{display:inline-flex;border:2px solid var(--ink);background:var(--paper);}
.seg button{
  height:34px;
  padding:0 .85rem;
  border:0;
  background:transparent;
  color:var(--ink);
  font:600 .82rem var(--f-sans);
  cursor:pointer;
  white-space:nowrap;
}
.seg button + button{border-left:2px solid var(--ink);}
.seg button:hover{background:#fff;}
.seg button.on{background:var(--ink);color:var(--paper);}

/* ПАНЕЛЬ ФИЛЬТРОВ */
.fbar{display:grid;gap:.9rem;border-top:1px dashed rgba(26,28,24,.35);padding-top:.9rem;}
.filter-deck > .fbar:first-child{border-top:0;padding-top:0;}
.fbar-label{display:block;font:700 .68rem var(--f-sans);letter-spacing:.09em;text-transform:uppercase;color:var(--teal);margin-bottom:.35rem;}

.chips{display:flex;flex-wrap:wrap;gap:.45rem;}
.chip{
  height:32px;
  padding:0 .8rem;
  border:2px solid var(--ink);
  background:var(--paper);
  color:var(--ink);
  font:600 .8rem var(--f-sans);
  cursor:pointer;
  display:inline-flex;
  align-items:center;
  gap:.5rem;
}
.chip .cnt{font:500 .72rem var(--f-mono);color:var(--muted);}
.chip:hover{background:#fff;}
.chip.on{background:var(--ink);color:var(--paper);}
.chip.on .cnt{color:var(--teal-hi);}

.fbar-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:.8rem 1rem;align-items:end;}
.ff[hidden]{display:none;}
.ff-search{grid-column:1 / -1;}

.fsel{position:relative;}
.fsel-btn{width:100%;display:flex;justify-content:space-between;align-items:center;gap:.5rem;cursor:pointer;text-align:left;}
.fsel-btn .v{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.fsel-btn .caret{font-size:.7rem;color:var(--muted);}
.fsel.active .fsel-btn{border-color:var(--copper);background:#fff;}
.fsel-pop{
  display:none;
  position:absolute;
  top:calc(100% + 4px);
  left:0;
  min-width:100%;
  width:max-content;
  max-width:340px;
  z-index:50;
  background:var(--paper-3);
  border:2px solid var(--ink);
  box-shadow:4px 4px 0 var(--ink);
  padding:.5rem;
}
.fsel.open .fsel-pop{display:block;}
.fsel-search{width:100%;height:32px;font-weight:500;margin-bottom:.4rem;}
.fsel-list{max-height:240px;overflow:auto;}
.fsel-opt{
  display:grid;
  grid-template-columns:18px 1fr auto;
  gap:.55rem;
  align-items:center;
  padding:.38rem .45rem;
  cursor:pointer;
  font:500 .8rem var(--f-mono);
}
.fsel-opt:hover{background:rgba(200,90,40,.12);}
.fsel-opt input{accent-color:var(--copper);width:15px;height:15px;}
.fsel-opt .n{color:var(--muted);font-size:.72rem;}
.fsel-empty{padding:.5rem;color:var(--muted);font-size:.82rem;}
.fsel-foot{margin-top:.4rem;padding-top:.4rem;border-top:1px dashed rgba(26,28,24,.35);display:flex;justify-content:flex-end;}

.fbar-foot{display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap;}
.fbar-actions{display:flex;flex-wrap:wrap;align-items:center;gap:.6rem;}
.btn-action.btn-sm{height:32px;padding:0 .9rem;font-size:.7rem;background:var(--ink);color:var(--paper);box-shadow:2px 2px 0 var(--copper);}
.btn-action.btn-sm:hover{background:var(--copper-deep);color:#fff;}
.fcount{font:500 .82rem var(--f-sans);color:var(--muted);}
.fcount b{color:var(--ink);font-family:var(--f-mono);}

/* ТАБЛИЦА ЛОГА */
.log-table-wrap{
  background:#111210;
  color:#cdd1c7;
  height:520px;
  overflow:auto;
  border:3px solid var(--ink);
  box-shadow:5px 5px 0 var(--ink);
}
.log-table{
  width:100%;
  border-collapse:separate;
  border-spacing:0;
  font:400 .72rem/1.25 var(--f-mono);
}
.log-table th{
  position:sticky;
  top:0;
  z-index:2;
  background:#1a1c18;
  color:var(--teal-hi);
  padding:.65rem .55rem;
  text-align:left;
  font:700 .62rem var(--f-sans);
  letter-spacing:.07em;
  text-transform:uppercase;
  border-bottom:2px solid #3a3d36;
  white-space:nowrap;
}
.log-table td{
  padding:.45rem .55rem;
  border-bottom:1px solid #22251f;
  white-space:nowrap;
  vertical-align:middle;
}
.log-table tbody tr:nth-child(even) td{background:rgba(255,255,255,.02);}
.log-table tbody tr:hover td{background:rgba(255,255,255,.07);}
.log-table tr.is-fail td:first-child{box-shadow:inset 3px 0 0 var(--copper-hi);}
.log-table tr.is-ok td:first-child{box-shadow:inset 3px 0 0 #4f8a57;}
.log-table .num{color:#6d7268;text-align:right;}
.log-table th.num{text-align:right;}
.log-table .dim{color:#5d6158;}
.log-table .t-date{color:#8d9287;}
.log-table .t-time{color:#e3e6dc;}
.log-table .c-proc{color:#aab0a3;}
.log-table .c-user{color:#eceee5;font-weight:700;}
.log-table .c-ip{color:#eceee5;font-weight:700;}
.log-table .c-file{color:var(--teal-hi);}
.log-table .c-det{color:#aab0a3;white-space:normal;min-width:190px;}

.status-tag{
  display:inline-block;
  min-width:68px;
  text-align:center;
  padding:.18rem .4rem;
  border-radius:3px;
  font:700 .66rem var(--f-mono);
}
.st-invalid,.st-failed{color:var(--copper-hi);background:rgba(224,106,52,.14);}
.st-accepted,.st-session{color:#8ec98e;background:rgba(142,201,142,.13);}
.st-info{color:#8fa1a8;background:rgba(143,161,168,.1);}

.more-row{display:flex;justify-content:space-between;align-items:center;gap:1rem;margin-top:.9rem;}
.more-row[hidden]{display:none;}

/* ТАБЛИЦЫ СТАТИСТИКИ */
.tbl{width:100%;border-collapse:collapse;font:400 .88rem var(--f-sans);margin-top:1rem;}
.tbl th{background:var(--ink);color:var(--paper);text-align:left;padding:.7rem .9rem;text-transform:uppercase;font:700 .7rem var(--f-sans);letter-spacing:.08em;}
.tbl td{padding:.65rem .9rem;border-bottom:1px solid rgba(28,29,26,.3);vertical-align:middle;}
.tbl tr:hover td{background:rgba(200,90,40,.07);}
.tbl .mono{font:700 .82rem var(--f-mono);}
.pill{display:inline-block;padding:.15rem .55rem;border:2px solid currentColor;font:700 .72rem var(--f-sans);letter-spacing:.05em;white-space:nowrap;}
.pill.bad{color:var(--copper-deep);}
.pill.good{color:var(--teal);}
.pill.err{color:var(--danger);}

.tbl .sub{display:block;margin-top:.2rem;font-size:.78rem;color:var(--muted);}
.tbl-note{margin-top:.7rem;font-size:.8rem;color:var(--muted);}
.pill.na{color:var(--muted);}
details.res summary{cursor:pointer;list-style:none;display:inline-flex;align-items:center;gap:.5rem;font:600 .82rem var(--f-sans);padding:.2rem 0;}
details.res summary::-webkit-details-marker{display:none;}
details.res summary::before{content:'▸';font-size:.7rem;color:var(--copper-deep);transition:transform .12s;}
details.res[open] summary::before{transform:rotate(90deg);}
.tbl .mini{width:auto;min-width:340px;border-collapse:collapse;margin-top:.45rem;}
.tbl .mini th{background:none;color:var(--teal);font:700 .64rem var(--f-sans);letter-spacing:.07em;text-transform:uppercase;padding:.25rem .9rem .25rem 0;border-bottom:1px solid rgba(26,28,24,.45);}
.tbl .mini td{padding:.3rem .9rem .3rem 0;border-bottom:1px dashed rgba(26,28,24,.25);font-size:.82rem;}
.tbl .mini .m-ok{color:var(--teal);font-weight:700;}
.tbl .mini .m-bad{color:var(--copper-deep);font-weight:700;}
.tbl .mini small{display:block;color:var(--muted);font-size:.7rem;}

/* МЕТРИКИ */
.metric-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem;margin-bottom:1.5rem;}
.metric-card{border:2px solid var(--ink);background:var(--paper);padding:.9rem;box-shadow:4px 4px 0 var(--ink);}
.metric-card .lab{font:700 .7rem var(--f-sans);letter-spacing:.07em;color:var(--muted);text-transform:uppercase;}
.metric-card .val{font:700 2.4rem/1 var(--f-serif);margin-top:.4rem;color:var(--ink);}
.metric-card .val.warn{color:var(--copper-deep);}

/* МОДАЛЬНОЕ ОКНО */
.modal-overlay{position:fixed;inset:0;background:rgba(26,28,24,.75);display:none;place-items:center;z-index:999;}
.modal-card{background:var(--paper-3);border:4px solid #b71c1c;box-shadow:8px 8px 0 var(--ink);padding:1.8rem;max-width:500px;width:90%;}
.modal-card h3{color:#b71c1c;font:700 1.4rem var(--f-serif);text-transform:uppercase;margin-bottom:.8rem;border-bottom:2px solid #b71c1c;padding-bottom:.4rem;}
.modal-card p{margin-bottom:1.2rem;font-size:.92rem;line-height:1.45;}

@page{size:A4 landscape;margin:12mm;}
@media print{
  *{-webkit-print-color-adjust:exact;print-color-adjust:exact;}
  html,body{background:#fff!important;background-image:none!important;color:#000!important;font-size:10pt;overflow:visible!important;padding:0!important;}
  .mast,.app-grid > div:first-child,.filter-deck,.btn-action,.more-row,.panel-head .tag{display:none!important;}
  .app-grid{display:block!important;padding:0!important;}
  .panel{border:0!important;box-shadow:none!important;background:#fff!important;padding:0!important;margin:0 0 1rem!important;}
  .panel-head{font-size:13pt!important;border-bottom:1.5px solid #000!important;margin-bottom:.5rem!important;break-after:avoid;}
  .print-header{display:block!important;margin-bottom:1rem;border-bottom:2px solid #000;padding-bottom:.5rem;}
  .metric-grid{gap:.5rem!important;margin-bottom:.8rem!important;}
  .metric-card{box-shadow:none!important;border:1px solid #000!important;background:#fff!important;padding:.4rem .6rem!important;}
  .metric-card .val{font-size:18pt!important;}

  .log-table-wrap{height:auto!important;overflow:visible!important;border:1px solid #000!important;box-shadow:none!important;background:#fff!important;}
  .log-table{min-width:0!important;width:100%!important;table-layout:auto!important;font-size:7pt!important;}
  .log-table col{width:auto!important;}
  .log-table thead{display:table-header-group;}
  .log-table tr{break-inside:avoid;}
  .log-table th{position:static!important;background:#eee!important;color:#000!important;border-bottom:1px solid #000!important;padding:3px 5px!important;font-size:6.5pt!important;}
  .log-table td{white-space:normal!important;overflow:visible!important;text-overflow:clip!important;word-break:break-word;color:#000!important;background:#fff!important;border-bottom:1px solid #ccc!important;padding:2px 5px!important;}
  .log-table tbody tr:nth-child(even) td{background:#f5f5f5!important;}
  .log-table tr.is-fail td:first-child{box-shadow:inset 3px 0 0 #9e3e14!important;}
  .log-table tr.is-ok td:first-child{box-shadow:none!important;}
  .log-table .c-time,.log-table .c-ip,.log-table .c-port,.log-table .c-file,.log-table .num,.log-table .status-tag{white-space:nowrap!important;}
  .log-table .t-date,.log-table .t-time,.log-table .c-proc,.log-table .c-det,.log-table .c-file,.log-table .c-user,.log-table .c-ip,.log-table .num{color:#000!important;}
  .log-table .dim{color:#777!important;}
  .log-table .status-tag{border:1px solid #000;background:#fff!important;color:#000!important;min-width:0!important;padding:0 4px!important;border-radius:2px;}
  .log-table .st-failed,.log-table .st-invalid{color:#9e3e14!important;border-color:#9e3e14!important;}

  .tbl{font-size:8pt!important;}
  .tbl th{background:#eee!important;color:#000!important;}
  .tbl tr{break-inside:avoid;}
}
.print-header{display:none;}
</style>
</head>
<body>

<div class="modal-overlay" id="errModal">
  <div class="modal-card">
    <h3>[ОШИБКА ВВОДА ПАРАМЕТРОВ]</h3>
    <p id="errModalText">Текст ошибки...</p>
    <button class="btn-action" style="width:100%;" onclick="closeErrorModal()">ПОНЯТНО / ИСПРАВИТЬ</button>
  </div>
</div>

<header class="mast">
  <div class="brand">ЖУРНАЛ ИБ // <span>АНАЛИЗАТОР</span></div>

  <div class="nav-cluster">
    <button type="button" class="nav-tab-btn active" id="tabBtnFile" onclick="switchMainTab('file')">СТАТИСТИКА ПО ФАЙЛАМ</button>
    <button type="button" class="nav-tab-btn" id="tabBtnSummary" onclick="switchMainTab('summary')">ОБЩАЯ СТАТИСТИКА</button>
  </div>

  <div class="status-badge"><span>●</span> СТАТУС: АКТИВЕН</div>
</header>

<main class="app-grid">
  <!-- ЛЕВАЯ КОЛОНКА -->
  <div>
    <div class="panel">
      <div class="panel-head">
        <span>ЖУРНАЛЫ</span>
        <span class="tag" id="filesCountLabel">// ФАЙЛОВ: 0</span>
      </div>
      <div class="file-list" id="filesContainer"></div>
    </div>
  </div>

  <!-- ПРАВАЯ РАБОЧАЯ ОБЛАСТЬ -->
  <div>
    <div class="print-header" id="printReportHeader">
      <h2 style="font-family:var(--f-serif); text-transform:uppercase; font-size:1.6rem; font-weight:700;">ОТЧЁТ ПО РЕЗУЛЬТАТАМ АУДИТА СИСТЕМНЫХ ЖУРНАЛОВ</h2>
      <p style="font-size:.9rem;" id="printMetaDetails">Дата генерации: —</p>
    </div>

    <!-- Вкладка 1: статистика по файлу -->
    <div id="tabContentFile">
      <div class="panel panel--alt">
        <div class="panel-head">
          <span id="selectedFileTitle">ВЫБЕРИТЕ ФАЙЛ</span>
          <span class="tag" id="selectedFileBadge">// СТАТУС</span>
        </div>

        <div id="fileDetailBox" style="display:none;">
          <div class="metric-grid">
            <div class="metric-card"><div class="lab">Всего строк лога</div><div class="val" id="fStatLines">0</div></div>
            <div class="metric-card"><div class="lab">Неудачных попыток</div><div class="val warn" id="fStatFailures">0</div></div>
            <div class="metric-card"><div class="lab">Успешных входов</div><div class="val" id="fStatAuths">0</div></div>
            <div class="metric-card"><div class="lab">Превышений порога</div><div class="val warn" id="fStatAlerts">0</div></div>
          </div>

          <div class="filter-deck">
            <div class="filter-row">
              <div class="param-unit">
                <label for="thresholdInput">Пороговое число сбоев</label>
                <input type="text" class="ctl" id="thresholdInput" value="5" style="width:72px;" onkeydown="if(event.key==='Enter')validateAndReanalyze()">
              </div>

              <div class="param-unit">
                <label for="windowInput">Временное окно</label>
                <div class="seg" role="group" aria-label="Формат окна">
                  <button type="button" id="segMin" class="on" onclick="setWinMode('MIN')">Минуты</button>
                  <button type="button" id="segHms" onclick="setWinMode('HMS')">ЧЧ:ММ:СС</button>
                </div>
                <input type="text" class="ctl" id="windowInput" value="60" style="width:110px;" onkeydown="if(event.key==='Enter')validateAndReanalyze()">
                <span class="hint" id="winMaxHint">макс: — мин</span>
              </div>

              <button class="btn-action" onclick="validateAndReanalyze()">Применить</button>
            </div>

            <div id="fileFilters"></div>
          </div>

          <div class="log-table-wrap">
            <table class="log-table">
              <thead>
                <tr>
                  <th class="num">№</th>
                  <th>Дата и время</th>
                  <th>Узел</th>
                  <th>Процесс</th>
                  <th>Статус</th>
                  <th>Пользователь</th>
                  <th>IP-источник</th>
                  <th>Порт</th>
                  <th>Детали</th>
                </tr>
              </thead>
              <tbody id="logTableBody"></tbody>
            </table>
          </div>

          <div class="panel-head" style="margin-top:2.2rem;">
            <span>ИТОГОВАЯ СТАТИСТИКА АКТИВНОСТИ IP</span>
            <span class="tag">// СВОДКА ПО ФАЙЛУ</span>
          </div>
          <table class="tbl">
            <thead>
              <tr>
                <th style="width:180px;">IP источника</th>
                <th style="width:120px;">Число сбоев</th>
                <th style="width:90px;">Порог</th>
                <th style="width:140px;">Статус</th>
                <th>Информация системы / предупреждение</th>
              </tr>
            </thead>
            <tbody id="ipSummaryBody"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Вкладка 2: общая статистика -->
    <div id="tabContentSummary" style="display:none;">
      <div class="panel panel--alt">
        <div class="panel-head">
          <span>ОБЩАЯ СТАТИСТИКА ПО ВСЕМ ЛОГАМ</span>
          <span class="tag">// МАССОВЫЙ АУДИТ</span>
        </div>

        <div class="metric-grid">
          <div class="metric-card"><div class="lab">Обработано файлов</div><div class="val" id="mTotalFiles">0</div></div>
          <div class="metric-card"><div class="lab">Суммарно строк</div><div class="val" id="mTotalLines">0</div></div>
          <div class="metric-card"><div class="lab">Всего сбоев входа</div><div class="val warn" id="mTotalFailures">0</div></div>
          <div class="metric-card"><div class="lab">Файлов с атаками</div><div class="val warn" id="mFilesWithAlerts">0</div></div>
        </div>

        <div class="panel-head" style="margin-top:1rem;">
          <span>ТАБЛИЦА РЕЗУЛЬТАТОВ ТЕСТИРОВАНИЯ</span>
          <span class="tag">// СВОДНЫЙ ОТЧЁТ</span>
        </div>
        <table class="tbl">
          <thead>
            <tr>
              <th style="width:100px;">Имя файла</th>
              <th style="width:120px;">Наличие алерта</th>
              <th style="width:150px;">Тест</th>
              <th>Результат</th>
              <th>Примечание</th>
            </tr>
          </thead>
          <tbody id="summaryTableBody"></tbody>
        </table>
        <p class="tbl-note">Тест всегда выполняется при пороге 5 и полном окне, независимо от настроек выше. «Ожидалось» определено вручную по содержимому файла. «Из N» означает: IP — из всех IP со сбоями, сбои — из всех попыток входа (сбои + успешные).</p>

        <div class="panel-head" style="margin-top:2.5rem;">
          <span>ОБЩИЙ СПИСОК ЖУРНАЛОВ (ВСЕ ФАЙЛЫ)</span>
          <span class="tag">// ПОТОК СОБЫТИЙ</span>
        </div>

        <div class="filter-deck">
          <div id="allFilters"></div>
        </div>

        <div class="log-table-wrap">
          <table class="log-table">
            <thead>
              <tr>
                <th>Файл</th>
                <th class="num">№</th>
                <th>Дата и время</th>
                <th>Узел</th>
                <th>Процесс</th>
                <th>Статус</th>
                <th>Пользователь</th>
                <th>IP-источник</th>
                <th>Порт</th>
                <th>Детали</th>
              </tr>
            </thead>
            <tbody id="allLogsTableBody"></tbody>
          </table>
        </div>

        <div class="more-row" id="allMoreRow" hidden>
          <span class="fcount" id="allMoreInfo"></span>
          <button type="button" class="btn-ghost" onclick="showMoreAll()">Показать ещё 300</button>
        </div>
      </div>
    </div>

  </div>
</main>

<script>
var state = null;
var currentFile = null;
var activeTab = 'file';
var validThreshold = 5;
var validWindowMinutes = 60;
var winMode = 'MIN';
var barFile = null;
var PAGE_STEP = 300;
var allLimit = PAGE_STEP;

var STATUS_LABEL = { Failed: 'Failed', Invalid: 'Invalid', Accepted: 'Accepted', Session: 'Session', INFO: 'Прочее' };
var STATUS_ORDER = ['Failed', 'Invalid', 'Accepted', 'Session', 'INFO'];

function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function pad2(n) { return String(n).padStart(2, '0'); }

/* ============================ ПАНЕЛЬ ФИЛЬТРОВ ============================ */
/* Значения IP / пользователь / служба / узел / файл подтягиваются из самих логов */
function createFilterBar(root, fields, onChange, exportScope) {
  var sel = {};
  var statuses = new Set();
  var query = '';
  var source = [];
  fields.forEach(function (f) { sel[f.key] = new Set(); });

  var html = '<div><span class="fbar-label">Статус операции</span><div class="chips"></div></div><div class="fbar-grid">';
  fields.forEach(function (f) {
    html += '<div class="ff" data-key="' + f.key + '"><span class="fbar-label">' + f.label + '</span>' +
      '<div class="fsel"><button type="button" class="ctl fsel-btn"><span class="v">Все</span><span class="caret">▾</span></button>' +
      '<div class="fsel-pop"><input type="text" class="ctl fsel-search" placeholder="Найти значение…">' +
      '<div class="fsel-list"></div>' +
      '<div class="fsel-foot"><button type="button" class="btn-ghost" data-act="clear">Очистить</button></div>' +
      '</div></div></div>';
  });
  html += '<div class="ff ff-search"><span class="fbar-label">Поиск по тексту строки</span>' +
    '<input type="text" class="ctl q" style="width:100%;" placeholder="Любая часть строки: IP, пользователь, служба, порт…"></div></div>' +
    '<div class="fbar-foot"><span class="fcount"></span><div class="fbar-actions">' +
    '<button type="button" class="btn-ghost" data-act="reset">Сбросить фильтры</button>' +
    '<button type="button" class="btn-action btn-sm" data-act="export">Экспорт отчёта в PDF</button></div></div>';
  root.classList.add('fbar');
  root.innerHTML = html;

  var chipsEl = root.querySelector('.chips');
  var countEl = root.querySelector('.fcount');
  var qEl = root.querySelector('.q');

  function ffEl(key) { return root.querySelector('.ff[data-key="' + key + '"]'); }
  function closeAll() {
    Array.prototype.forEach.call(root.querySelectorAll('.fsel.open'), function (b) { b.classList.remove('open'); });
  }

  function updateLabel(f) {
    var s = sel[f.key];
    var ff = ffEl(f.key);
    ff.querySelector('.fsel-btn .v').textContent = s.size === 0 ? 'Все' : (s.size === 1 ? Array.from(s)[0] : 'Выбрано: ' + s.size);
    ff.querySelector('.fsel').classList.toggle('active', s.size > 0);
  }

  function refreshChips() {
    var cnt = {};
    source.forEach(function (r) { cnt[r.opStatus] = (cnt[r.opStatus] || 0) + 1; });
    Array.from(statuses).forEach(function (s) { if (!cnt[s]) statuses.delete(s); });
    var h = '<button type="button" class="chip' + (statuses.size === 0 ? ' on' : '') + '" data-st="*">Все <span class="cnt">' + source.length + '</span></button>';
    STATUS_ORDER.forEach(function (s) {
      if (cnt[s]) {
        h += '<button type="button" class="chip' + (statuses.has(s) ? ' on' : '') + '" data-st="' + s + '">' +
          STATUS_LABEL[s] + ' <span class="cnt">' + cnt[s] + '</span></button>';
      }
    });
    chipsEl.innerHTML = h;
  }

  function refreshFields() {
    fields.forEach(function (f) {
      var t = {};
      source.forEach(function (r) {
        var v = f.get(r);
        if (v && v !== '—') t[v] = (t[v] || 0) + 1;
      });
      var keys = Object.keys(t);
      Array.from(sel[f.key]).forEach(function (v) { if (!t[v]) sel[f.key].delete(v); });
      keys.sort(function (a, b) { return t[b] - t[a] || a.localeCompare(b, undefined, { numeric: true }); });

      var ff = ffEl(f.key);
      ff.hidden = !!f.hideSingle && keys.length < 2;
      ff.querySelector('.fsel-list').innerHTML = keys.length ? keys.map(function (k) {
        return '<label class="fsel-opt"><input type="checkbox" data-v="' + esc(k) + '"' + (sel[f.key].has(k) ? ' checked' : '') + '>' +
          '<span class="ov">' + esc(k) + '</span><span class="n">' + t[k] + '</span></label>';
      }).join('') : '<div class="fsel-empty">Нет значений</div>';
      ff.querySelector('.fsel-search').value = '';
      updateLabel(f);
    });
  }

  function reset(silent) {
    statuses.clear();
    fields.forEach(function (f) { sel[f.key].clear(); });
    query = '';
    qEl.value = '';
    refreshChips();
    refreshFields();
    if (!silent) onChange();
  }

  root.addEventListener('click', function (e) {
    var chip = e.target.closest('.chip');
    if (chip) {
      var st = chip.getAttribute('data-st');
      if (st === '*') statuses.clear();
      else if (statuses.has(st)) statuses.delete(st);
      else statuses.add(st);
      refreshChips();
      onChange();
      return;
    }
    var btn = e.target.closest('.fsel-btn');
    if (btn) {
      var box = btn.closest('.fsel');
      var wasOpen = box.classList.contains('open');
      closeAll();
      if (!wasOpen) { box.classList.add('open'); box.querySelector('.fsel-search').focus(); }
      return;
    }
    var act = e.target.closest('[data-act]');
    if (act) {
      var what = act.getAttribute('data-act');
      if (what === 'reset') {
        reset(false);
      } else if (what === 'export') {
        exportToPdf(exportScope);
      } else {
        var key = act.closest('.ff').getAttribute('data-key');
        sel[key].clear();
        refreshFields();
        onChange();
      }
      return;
    }
    if (!e.target.closest('.fsel')) closeAll();
  });

  root.addEventListener('change', function (e) {
    var cb = e.target;
    if (cb.type !== 'checkbox') return;
    var ff = cb.closest('.ff');
    var key = ff.getAttribute('data-key');
    var v = cb.getAttribute('data-v');
    if (cb.checked) sel[key].add(v); else sel[key].delete(v);
    fields.forEach(function (f) { if (f.key === key) updateLabel(f); });
    onChange();
  });

  root.addEventListener('input', function (e) {
    var t = e.target;
    if (t.classList.contains('q')) {
      query = t.value.toLowerCase().trim();
      onChange();
    } else if (t.classList.contains('fsel-search')) {
      var needle = t.value.toLowerCase().trim();
      Array.prototype.forEach.call(t.closest('.fsel-pop').querySelectorAll('.fsel-opt'), function (o) {
        o.style.display = o.querySelector('.ov').textContent.toLowerCase().indexOf(needle) >= 0 ? '' : 'none';
      });
    }
  });

  document.addEventListener('click', function (e) { if (!root.contains(e.target)) closeAll(); });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeAll(); });

  return {
    setSource: function (rows) { source = rows; refreshChips(); refreshFields(); },
    reset: reset,
    setCount: function (shown, total) { countEl.innerHTML = 'Найдено: <b>' + shown + '</b> из ' + total + ' записей'; },
    match: function (r) {
      if (statuses.size && !statuses.has(r.opStatus)) return false;
      for (var i = 0; i < fields.length; i++) {
        var s = sel[fields[i].key];
        if (s.size && !s.has(fields[i].get(r))) return false;
      }
      if (query && (r.fileName + ' ' + r.raw).toLowerCase().indexOf(query) < 0) return false;
      return true;
    }
  };
}

var F_IP = { key: 'ip', label: 'IP-адрес', get: function (r) { return r.ip; } };
var F_USER = { key: 'user', label: 'Пользователь', get: function (r) { return r.user; } };
var F_SERVICE = { key: 'service', label: 'Служба', get: function (r) { return r.service; } };
var F_HOST = { key: 'host', label: 'Узел', hideSingle: true, get: function (r) { return r.host; } };
var F_FILE = { key: 'fileName', label: 'Файл', get: function (r) { return r.fileName; } };

var fileBar = createFilterBar(document.getElementById('fileFilters'), [F_IP, F_USER, F_SERVICE, F_HOST], renderCurrentTable, 'file');
var allBar = createFilterBar(document.getElementById('allFilters'), [F_FILE, F_IP, F_USER, F_SERVICE, F_HOST], function () {
  allLimit = PAGE_STEP;
  renderAllLogsTable();
}, 'summary');

/* ============================ ВКЛАДКИ / ОКНА ============================ */
function switchMainTab(tab) {
  activeTab = tab;
  document.getElementById('tabBtnFile').classList.toggle('active', tab === 'file');
  document.getElementById('tabBtnSummary').classList.toggle('active', tab === 'summary');
  document.getElementById('tabContentFile').style.display = (tab === 'file') ? 'block' : 'none';
  document.getElementById('tabContentSummary').style.display = (tab === 'summary') ? 'block' : 'none';
  if (tab === 'summary') renderAllLogsTable();
}

function showErrorModal(msg) {
  document.getElementById('errModalText').textContent = msg;
  document.getElementById('errModal').style.display = 'grid';
}
function closeErrorModal() {
  document.getElementById('errModal').style.display = 'none';
}

/* ============================ ВРЕМЕННОЕ ОКНО ============================ */
function setWinMode(mode) {
  winMode = mode;
  document.getElementById('segMin').classList.toggle('on', mode === 'MIN');
  document.getElementById('segHms').classList.toggle('on', mode === 'HMS');
  var input = document.getElementById('windowInput');
  if (mode === 'HMS') {
    var t = validWindowMinutes * 60;
    input.value = pad2(Math.floor(t / 3600)) + ':' + pad2(Math.floor((t % 3600) / 60)) + ':' + pad2(t % 60);
  } else {
    input.value = String(validWindowMinutes);
  }
}

function validateAndReanalyze() {
  var thRaw = document.getElementById('thresholdInput').value.trim();
  var winRaw = document.getElementById('windowInput').value.trim();

  if (!thRaw || !/^\d+$/.test(thRaw)) {
    showErrorModal('Некорректное "Пороговое число сбоев": поле должно содержать только целое положительное число.');
    return;
  }
  var thVal = parseInt(thRaw, 10);
  if (thVal < 1) {
    showErrorModal('Пороговое число сбоев должно быть не меньше 1.');
    return;
  }

  var parsedMinutes = 0;
  if (winMode === 'MIN') {
    if (!winRaw || !/^\d+$/.test(winRaw)) {
      showErrorModal('Некорректное "Временное окно": введите положительное целое число минут.');
      return;
    }
    parsedMinutes = parseInt(winRaw, 10);
  } else {
    var match = /^(\d{1,2}):(\d{2}):(\d{2})$/.exec(winRaw);
    if (!match) {
      showErrorModal('Неверный формат времени: используйте строгий формат ЧЧ:ММ:СС (например, 00:15:00).');
      return;
    }
    var h = parseInt(match[1], 10), m = parseInt(match[2], 10), s = parseInt(match[3], 10);
    if (m >= 60 || s >= 60) {
      showErrorModal('В формате ЧЧ:ММ:СС минуты и секунды не могут превышать 59.');
      return;
    }
    parsedMinutes = Math.ceil((h * 3600 + m * 60 + s) / 60);
  }

  if (parsedMinutes <= 0) {
    showErrorModal('Временное окно должно быть строго больше 0.');
    return;
  }

  var cur = state && state.files.find(function (x) { return x.fileName === currentFile; });
  if (cur && cur.totalDurationMin > 0 && parsedMinutes > cur.totalDurationMin) {
    showErrorModal('Временное окно (' + parsedMinutes + ' мин) превышает общую длительность фиксации записей лога (' + cur.totalDurationMin + ' мин).');
    return;
  }

  validThreshold = thVal;
  validWindowMinutes = parsedMinutes;
  render();
}

function getCutoff(cur, winMinutes) {
  if (!cur.maxTime || !isFinite(winMinutes)) return null;
  return Date.parse(cur.maxTime) - winMinutes * 60000;
}

function windowRows(cur, winMinutes) {
  if (!cur || !cur.rows) return [];
  var cutoff = getCutoff(cur, winMinutes);
  if (cutoff === null) return cur.rows;
  return cur.rows.filter(function (r) { return r.ts === null || r.ts >= cutoff; });
}

function failuresByIp(rows) {
  var m = {};
  rows.forEach(function (r) {
    if (r.isFailure && r.ip !== '—') m[r.ip] = (m[r.ip] || 0) + 1;
  });
  return m;
}

function getBreachCountForFile(f, th, winMin) {
  if (f.status !== 'OK') return 0;
  var map = failuresByIp(windowRows(f, winMin));
  return Object.keys(map).filter(function (ip) { return map[ip] > th; }).length;
}

/* ============================ ЗАГРУЗКА / ОТРИСОВКА ============================ */
async function loadData() {
  try {
    var res = await fetch('/api/scan');
    state = await res.json();
    render();
  } catch (e) {
    showErrorModal('Не удалось связаться с сервером (API недоступно).');
  }
}

function render() {
  if (!state) return;
  var fc = document.getElementById('filesContainer');

  if (state.status !== 'SUCCESS') {
    fc.innerHTML = '<div class="empty">' + esc(state.error || 'Нет данных') + '</div>';
    return;
  }

  document.getElementById('filesCountLabel').textContent = '// ФАЙЛОВ: ' + state.files.length;
  fc.innerHTML = '';

  state.files.forEach(function (f) {
    var div = document.createElement('div');
    div.className = 'file-item' + (currentFile === f.fileName ? ' active' : '');

    var breachCount = getBreachCountForFile(f, validThreshold, validWindowMinutes);
    var badgeHtml = '<span class="badge clean">[АТАК: 0]</span>';
    if (f.status !== 'OK') badgeHtml = '<span class="badge err">[ОШИБКА]</span>';
    else if (breachCount > 0) badgeHtml = '<span class="badge alert">[АТАК: ' + breachCount + ']</span>';

    div.innerHTML = '<span class="fname">' + esc(f.fileName) + '</span>' + badgeHtml;
    div.onclick = function () {
      currentFile = f.fileName;
      switchMainTab('file');
      render();
    };
    fc.appendChild(div);
  });

  if (!currentFile && state.files.length > 0) currentFile = state.files[0].fileName;

  var cur = state.files.find(function (x) { return x.fileName === currentFile; });
  if (cur) {
    document.getElementById('fileDetailBox').style.display = 'block';
    document.getElementById('selectedFileTitle').textContent = cur.fileName;
    document.getElementById('selectedFileBadge').textContent = '// ' + (cur.status === 'OK' ? 'УСПЕШНО' : cur.error);
    document.getElementById('winMaxHint').textContent = 'макс: ' + cur.totalDurationMin + ' мин';

    var rows = windowRows(cur, validWindowMinutes);
    if (barFile !== cur.fileName) { fileBar.reset(true); barFile = cur.fileName; }
    fileBar.setSource(rows);

    renderFileStatsAndSummary(cur, rows);
    renderCurrentTable();
  }

  renderMassStats();

  var all = [];
  state.files.forEach(function (f) { if (f.rows) all = all.concat(f.rows); });
  allBar.setSource(all);
  if (activeTab === 'summary') renderAllLogsTable();
}

function renderFileStatsAndSummary(cur, rows) {
  var failures = 0, auths = 0;
  rows.forEach(function (r) {
    if (r.isFailure && r.ip !== '—') failures++;
    if (r.isSuccess) auths++;
  });
  var ipMap = failuresByIp(rows);
  var alerts = Object.keys(ipMap).filter(function (ip) { return ipMap[ip] > validThreshold; });

  document.getElementById('fStatLines').textContent = cur.totalLines;
  document.getElementById('fStatFailures').textContent = failures;
  document.getElementById('fStatAuths').textContent = auths;
  document.getElementById('fStatAlerts').textContent = alerts.length;

  var sorted = Object.keys(ipMap).map(function (ip) { return [ip, ipMap[ip]]; }).sort(function (a, b) { return b[1] - a[1]; });
  var html = '';
  if (sorted.length === 0) {
    html = '<tr><td colspan="5" style="text-align:center; color:var(--muted); padding:1rem;">Сбоев входа в выбранном окне не зафиксировано</td></tr>';
  } else {
    sorted.forEach(function (p) {
      var ip = p[0], count = p[1];
      var isBreach = count > validThreshold;
      var warn = isBreach
        ? '<b style="color:var(--copper-deep);">[ПРЕДУПРЕЖДЕНИЕ]</b> Зафиксирован перебор паролей (Brute-force). Попыток: <b>' + count + ' &gt; ' + validThreshold + '</b>'
        : 'Активность в пределах допустимой нормы';
      html += '<tr><td class="mono">' + esc(ip) + '</td><td>' + count + '</td><td>' + validThreshold + '</td>' +
        '<td><span class="pill ' + (isBreach ? 'bad' : 'good') + '">' + (isBreach ? '[АТАК: 1]' : '[АТАК: 0]') + '</span></td>' +
        '<td>' + warn + '</td></tr>';
    });
  }
  document.getElementById('ipSummaryBody').innerHTML = html;
}

/* ---------- строки таблиц ---------- */
function dim(v) { return v === '—' ? '<span class="dim">—</span>' : esc(v); }

function statusClass(s) {
  if (s === 'Invalid') return 'st-invalid';
  if (s === 'Failed') return 'st-failed';
  if (s === 'Accepted') return 'st-accepted';
  if (s === 'Session') return 'st-session';
  return 'st-info';
}

function rowHtml(r, withFile) {
  var cls = r.isFailure ? 'is-fail' : (r.opStatus === 'Accepted' ? 'is-ok' : '');
  var proc = r.service === '—' ? '—' : (r.pid !== '—' ? r.service + '[' + r.pid + ']' : r.service);
  var when = r.time === '—'
    ? '<span class="dim">—</span>'
    : '<span class="t-date">' + esc(r.month + ' ' + r.day) + '</span> <span class="t-time">' + esc(r.time) + '</span>';
  return '<tr class="' + cls + '" title="' + esc(r.raw) + '">' +
    (withFile ? '<td class="c-file">' + esc(r.fileName) + '</td>' : '') +
    '<td class="num">' + r.lineNum + '</td>' +
    '<td class="c-time">' + when + '</td>' +
    '<td>' + dim(r.host) + '</td>' +
    '<td class="c-proc">' + dim(proc) + '</td>' +
    '<td><span class="status-tag ' + statusClass(r.opStatus) + '">' + esc(r.opStatus) + '</span></td>' +
    '<td class="c-user">' + dim(r.user) + '</td>' +
    '<td class="c-ip">' + dim(r.ip) + '</td>' +
    '<td class="c-port">' + dim(r.port) + '</td>' +
    '<td class="c-det">' + esc(r.details) + '</td>' +
    '</tr>';
}

function renderCurrentTable() {
  var cur = state && state.files.find(function (x) { return x.fileName === currentFile; });
  if (!cur || !cur.rows) return;

  var rows = windowRows(cur, validWindowMinutes);
  var filtered = rows.filter(fileBar.match);
  fileBar.setCount(filtered.length, rows.length);

  var tb = document.getElementById('logTableBody');
  if (filtered.length === 0) {
    tb.innerHTML = '<tr><td colspan="9" style="text-align:center; padding:1.5rem; color:#8d9287;">Записей по заданным фильтрам не найдено</td></tr>';
    return;
  }
  tb.innerHTML = filtered.map(function (r) { return rowHtml(r, false); }).join('');
}

/* Ожидаемые результаты определены вручную по содержимому тестовых файлов (порог 5, полное окно) */
var EXPECTED_THRESHOLD = 5;
var EXPECTED = {
  'L1.txt': { alert: true,  ips: 6, ipsTotal: 7, fails: 46, attempts: 48, note: 'Перебор логинов (Invalid user) с 7 адресов, 6 из них выше порога. На фоне перебора есть 2 успешных входа (root, admin) с адресов-нарушителей.' },
  'L2.txt': { alert: false, ips: 0, ipsTotal: 2, fails: 2,  attempts: 19, note: 'Преимущественно успешные входы, 2 единичных сбоя, перебора нет. Вход служебных учёток (mysql, nginx) по паролю подозрителен, но вне критерия работы.' },
  'L3.txt': { alert: true,  ips: 6, ipsTotal: 7, fails: 51, attempts: 51, note: 'Массовый перебор паролей (Failed password) для известных учётных записей, 6 адресов выше порога. Успешных входов нет.' },
  'L4.txt': { alert: false, ips: 0, ipsTotal: 0, fails: 0,  attempts: 22, note: 'Только успешные входы, сбоев нет. Вход служебных учёток (mysql, nginx) по паролю вне критерия работы.' },
  'L5.txt': { alert: false, ips: 0, ipsTotal: 1, fails: 1,  attempts: 2,  note: 'Две некорректные строки должны быть пропущены без ошибки.' }
};

/* Фактический результат при эталонных параметрах (порог 5, весь файл) */
function referenceResult(f) {
  var fails = 0, accepted = 0;
  f.rows.forEach(function (r) {
    if (r.isFailure && r.ip !== '—') fails++;
    if (r.opStatus === 'Accepted') accepted++;
  });
  var map = failuresByIp(f.rows);
  var ipList = Object.keys(map);
  var ips = ipList.filter(function (ip) { return map[ip] > EXPECTED_THRESHOLD; }).length;
  return { alert: ips > 0, ips: ips, ipsTotal: ipList.length, fails: fails, attempts: fails + accepted };
}

function resultDetails(exp, act) {
  var rows = [
    { label: 'Алерт', hint: '', e: exp && (exp.alert ? 'ДА' : 'НЕТ'), a: act.alert ? 'ДА' : 'НЕТ' },
    { label: 'IP выше порога', hint: 'из IP со сбоями', e: exp && (exp.ips + ' из ' + exp.ipsTotal), a: act.ips + ' из ' + act.ipsTotal },
    { label: 'Сбоев входа', hint: 'из всех попыток входа', e: exp && (exp.fails + ' из ' + exp.attempts), a: act.fails + ' из ' + act.attempts }
  ];
  var ok = 0;
  var body = rows.map(function (r) {
    var match = exp ? r.e === r.a : null;
    if (match) ok++;
    return '<tr><td>' + r.label + (r.hint ? '<small>' + r.hint + '</small>' : '') + '</td>' +
      '<td>' + (exp ? r.e : '—') + '</td><td><b>' + r.a + '</b></td>' +
      '<td class="' + (match === null ? '' : (match ? 'm-ok' : 'm-bad')) + '">' + (match === null ? '' : (match ? '✓' : '✗')) + '</td></tr>';
  }).join('');
  var caption = exp ? 'Показатели: ' + ok + ' из ' + rows.length + ' совпали' : 'Показатели';
  return {
    passed: exp ? ok === rows.length : null,
    html: '<details class="res"><summary>' + caption + '</summary>' +
      '<table class="mini"><thead><tr><th>Показатель</th><th>Ожидалось</th><th>Факт</th><th></th></tr></thead><tbody>' + body + '</tbody></table></details>'
  };
}

function renderMassStats() {
  var massLines = 0, massFailures = 0, massAlertFiles = 0, html = '';

  state.files.forEach(function (f) {
    massLines += f.totalLines;
    var fileFails = 0;
    f.rows.forEach(function (r) { if (r.isFailure) fileFails++; });
    massFailures += fileFails;
    if (getBreachCountForFile(f, validThreshold, validWindowMinutes) > 0) massAlertFiles++;

    if (f.status !== 'OK') {
      html += '<tr><td class="mono">' + esc(f.fileName) + '</td>' +
        '<td><span class="pill err">ОШИБКА</span></td>' +
        '<td><span class="pill err">Файл не прочитан</span></td>' +
        '<td>' + esc(f.error) + '. Программа продолжила работу.</td><td>—</td></tr>';
      return;
    }

    var exp = EXPECTED[f.fileName];
    var act = referenceResult(f);
    var det = resultDetails(exp, act);
    var verdict = det.passed === null ? '<span class="pill na">Эталон не задан</span>'
      : (det.passed ? '<span class="pill good">✓ Пройден</span>' : '<span class="pill bad">✗ Не пройден</span>');

    html += '<tr>' +
      '<td class="mono">' + esc(f.fileName) + '</td>' +
      '<td><span class="pill ' + (act.alert ? 'bad' : 'good') + '">' + (act.alert ? 'ДА' : 'НЕТ') + '</span></td>' +
      '<td>' + verdict + '</td>' +
      '<td>' + det.html + '</td>' +
      '<td>' + (exp ? esc(exp.note) : '—') + '</td>' +
      '</tr>';
  });
  document.getElementById('summaryTableBody').innerHTML = html;

  document.getElementById('mTotalFiles').textContent = state.files.length;
  document.getElementById('mTotalLines').textContent = massLines;
  document.getElementById('mTotalFailures').textContent = massFailures;
  document.getElementById('mFilesWithAlerts').textContent = massAlertFiles;
}

function renderAllLogsTable() {
  if (!state || !state.files) return;
  var all = [];
  state.files.forEach(function (f) { if (f.rows) all = all.concat(f.rows); });

  var filtered = all.filter(allBar.match);
  allBar.setCount(filtered.length, all.length);

  var tb = document.getElementById('allLogsTableBody');
  var more = document.getElementById('allMoreRow');

  if (filtered.length === 0) {
    tb.innerHTML = '<tr><td colspan="10" style="text-align:center; padding:1.5rem; color:#8d9287;">Записей не найдено</td></tr>';
    more.hidden = true;
    return;
  }

  var shown = filtered.slice(0, allLimit);
  tb.innerHTML = shown.map(function (r) { return rowHtml(r, true); }).join('');
  more.hidden = filtered.length <= allLimit;
  document.getElementById('allMoreInfo').textContent = 'Показано ' + shown.length + ' из ' + filtered.length;
}

function showMoreAll() {
  allLimit += PAGE_STEP;
  renderAllLogsTable();
}

function exportToPdf(scope) {
  var now = new Date();
  var nowStr = pad2(now.getDate()) + '.' + pad2(now.getMonth() + 1) + '.' + now.getFullYear() + ' ' +
    pad2(now.getHours()) + ':' + pad2(now.getMinutes()) + ':' + pad2(now.getSeconds());

  var metaEl = document.getElementById('printMetaDetails');
  if (scope === 'file') {
    metaEl.textContent = 'Дата генерации: ' + nowStr + ' | Объект: ' + currentFile + ' | Порог: ' + validThreshold +
      ' | Окно: ' + validWindowMinutes + ' мин. | ' + document.querySelector('#fileFilters .fcount').textContent;
  } else {
    metaEl.textContent = 'Дата генерации: ' + nowStr + ' | Сводный отчёт по всем журналам | Порог: ' + validThreshold +
      ' | Окно: ' + validWindowMinutes + ' мин. | ' + document.querySelector('#allFilters .fcount').textContent;
  }

  // в отчёт попадают все отфильтрованные строки, а не только первые 300
  var oldTitle = document.title;
  var oldLimit = allLimit;
  document.title = 'Отчёт ИБ — ' + (scope === 'file' ? currentFile : 'сводный');
  if (scope === 'summary') { allLimit = Infinity; renderAllLogsTable(); }

  var dets = [].slice.call(document.querySelectorAll('details.res'));
  var wasOpen = dets.map(function (d) { return d.open; });
  dets.forEach(function (d) { d.open = true; });

  window.onafterprint = function () {
    window.onafterprint = null;
    dets.forEach(function (d, i) { d.open = wasOpen[i]; });
    document.title = oldTitle;
    allLimit = oldLimit;
    if (scope === 'summary') renderAllLogsTable();
  };
  window.print();
}

loadData();
</script>
</body>
</html>`;

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (url.pathname === '/api/scan') {
    const scan = scanLogsDirectory();
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    return res.end(JSON.stringify(scan));
  }

  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(PAGE);
});

server.listen(PORT, () => {
  console.log(`[✓] СЕРВЕР ЗАПУЩЕН: http://localhost:${PORT}`);
});
