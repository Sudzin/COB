import { esc } from '../utils/esc.js';
import { fmtNum } from '../utils/fmtNum.js';
import { fmtDuration } from '../utils/fmtDuration.js';
import { CATEGORY_ORDER, CATEGORY_LABEL } from '../constants.js';

/** Карточки метрик, итоговая классификация по категориям и список инцидентов. */
export function renderTrafficSummary(cur) {
  const set = (id, v) => { document.getElementById(id).textContent = v; };
  set('tPackets', fmtNum(cur.totalPackets));
  set('tBytes', fmtNum(cur.totalBytes));
  set('tFlows', fmtNum(cur.totalFlows));
  set('tDuration', fmtDuration(cur.duration));
  set('tIncidents', fmtNum(cur.incidents.length));

  const notes = [];
  if (cur.ignoredPackets > 0) notes.push('Пропущено пакетов без IP + TCP/UDP/ICMP: ' + fmtNum(cur.ignoredPackets) + '.');
  if (cur.truncated) notes.push('Файл оборван на последней записи — разобрано то, что успело сохраниться.');
  if (cur.sampled) notes.push('Точки на графиках прорежены (очень много пакетов); таблицы и счётчики считаются по всем.');
  if (cur.flowsTruncated) notes.push('В таблице показаны самые крупные потоки; всего потоков: ' + fmtNum(cur.totalFlows) + '.');
  document.getElementById('trafficNote').textContent = notes.join(' ');

  document.getElementById('trafficCatBody').innerHTML = CATEGORY_ORDER.map(c => {
    const s = cur.categories[c];
    const share = cur.totalPackets ? (s.packets / cur.totalPackets * 100).toFixed(1) + '%' : '—';
    return '<tr><td><span class="pill cat-' + c + '">' + CATEGORY_LABEL[c] + '</span></td>' +
      '<td class="num">' + fmtNum(s.flows) + '</td><td class="num">' + fmtNum(s.packets) + '</td>' +
      '<td class="num">' + fmtNum(s.bytes) + '</td><td class="num">' + share + '</td></tr>';
  }).join('');

  const box = document.getElementById('trafficIncidents');
  if (!cur.incidents.length) {
    box.innerHTML = '<div class="empty">Аномалий не обнаружено: весь трафик классифицирован как легитимный.</div>';
    return;
  }
  const rel = t => '+' + fmtDuration(Math.max(0, t - cur.t0));
  box.innerHTML = cur.incidents.map(i =>
    '<div class="incident inc-' + i.type + '">' +
      '<div class="inc-head"><span class="pill cat-' + i.type + '">' + esc(i.title) + '</span>' +
      '<b class="mono">' + esc(i.src) + ' → ' + esc(i.dst) + '</b></div>' +
      '<p>' + esc(i.description) + '</p>' +
      '<div class="inc-meta">Потоков: ' + fmtNum(i.flows) + ' · Пакетов: ' + fmtNum(i.packets) +
      ' · Интервал от начала захвата: ' + rel(i.start_time) + ' … ' + rel(i.end_time) + '</div>' +
    '</div>'
  ).join('');
}
