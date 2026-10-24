import { esc } from '../utils/esc.js';
import { dim } from './helpers/dim.js';
import { statusClass } from './helpers/statusClass.js';

/** HTML одной строки таблицы журнала. withFile — добавить колонку «Файл» (общий список). */
export function rowHtml(r, withFile) {
  const cls = r.isFailure ? 'is-fail' : (r.opStatus === 'Accepted' ? 'is-ok' : '');
  const proc = r.service === '—' ? '—' : (r.pid !== '—' ? r.service + '[' + r.pid + ']' : r.service);
  const when = r.time === '—'
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
