import { store } from '../state.js';
import { esc } from '../utils/esc.js';
import { fmtNum } from '../utils/fmtNum.js';
import { fmtRate } from '../utils/fmtRate.js';
import { fmtEndpoint } from '../utils/fmtEndpoint.js';
import { CATEGORY_LABEL } from '../constants.js';

const SORTERS = {
  packets: (a, b) => b.packets - a.packets || b.bytes - a.bytes,
  bytes: (a, b) => b.bytes - a.bytes,
  duration: (a, b) => b.duration - a.duration,
  pps: (a, b) => (b.pps || 0) - (a.pps || 0),
  start: (a, b) => a.start_time - b.start_time
};

/** Таблица потоков: фильтр по категории, сортировка, «показать ещё». */
export function renderFlowTable(cur) {
  let rows = cur.flows;
  if (store.trafficCategory !== 'all') rows = rows.filter(f => f.category === store.trafficCategory);
  rows = rows.slice().sort(SORTERS[store.trafficSort] || SORTERS.packets);

  const shown = rows.slice(0, store.trafficLimit);
  document.getElementById('trafficFlowBody').innerHTML = shown.map(rowHtml).join('') ||
    '<tr><td colspan="11" class="empty">Нет потоков в выбранной категории</td></tr>';

  const more = rows.length - shown.length;
  document.getElementById('trafficFlowCount').innerHTML =
    'Показано <b>' + fmtNum(shown.length) + '</b> из <b>' + fmtNum(rows.length) + '</b> потоков';
  document.getElementById('trafficMoreRow').hidden = more <= 0;
}

function rowHtml(f) {
  const syn = (f.syn_ratio * 100).toFixed(0) + '%';
  const flow = esc(fmtEndpoint(f.proto, f.src, f.sport)) + ' → ' + esc(fmtEndpoint(f.proto, f.dst, f.dport));
  return '<tr>' +
    '<td><span class="pill cat-' + f.category + '" title="' + esc(f.reasons.join('; ')) + '">' + CATEGORY_LABEL[f.category] + '</span></td>' +
    '<td>' + f.proto + '</td>' +
    '<td class="mono">' + flow + '</td>' +
    '<td class="num">' + fmtNum(f.packets) + '<span class="sub">' + fmtNum(f.fwd.packets) + ' → · ' + fmtNum(f.rev.packets) + ' ←</span></td>' +
    '<td class="num">' + fmtNum(f.bytes) + '</td>' +
    '<td class="num">' + f.duration.toFixed(3) + '</td>' +
    '<td class="num">' + fmtRate(f.pps) + '</td>' +
    '<td class="num">' + fmtRate(f.bps) + '</td>' +
    '<td class="num">' + syn + '</td>' +
    '<td class="num">' + f.avg_size.toFixed(1) + '</td>' +
    '<td class="num">' + f.syn_count + '/' + f.ack_count + '/' + f.rst_count + '/' + f.fin_count + '</td>' +
  '</tr>';
}
