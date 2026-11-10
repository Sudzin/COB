import { PROTO_COLOR } from '../constants.js';
import { drawHistogram } from './charts/drawHistogram.js';
import { drawBars } from './charts/drawBars.js';
import { drawScatter } from './charts/drawScatter.js';
import { drawTopFlows } from './charts/drawTopFlows.js';

const FLAG_COLOR = { SYN: '#ab1f1f', ACK: '#3f6168', PSH: '#c85a28', RST: '#6b4c9a', FIN: '#575952' };

/** Четыре графика вкладки «Трафик» (SVG, без внешних библиотек). */
export function renderTrafficCharts(cur) {
  const put = (id, html) => { document.getElementById(id).innerHTML = html; };

  put('chartHist', drawHistogram(cur.sizes));
  put('chartProto', drawBars(
    Object.entries(cur.protocols).map(([label, value]) => ({ label, value, color: PROTO_COLOR[label] })),
    { yLabel: 'Количество пакетов', percent: true }
  ));
  put('chartFlags', drawBars(
    Object.entries(cur.flags).map(([label, value]) => ({ label, value, color: FLAG_COLOR[label] })),
    { yLabel: 'Количество пакетов', percent: false }
  ));
  put('chartTimeline', drawScatter(cur.timeline, cur.duration));
  put('chartTop', drawTopFlows(cur.flows));
}
