import { esc } from '../../utils/esc.js';
import { niceTicks } from '../../utils/niceTicks.js';
import { noData } from './noData.js';

const W = 360, H = 300, M = { l: 56, r: 12, t: 22, b: 44 };

/**
 * Столбчатая диаграмма. items: [{label, value, color}].
 * percent: подписывать долю от суммы (для протоколов).
 */
export function drawBars(items, { yLabel = '', percent = false } = {}) {
  const total = items.reduce((acc, it) => acc + it.value, 0);
  if (!total) return noData();

  const ticks = niceTicks(Math.max(...items.map(i => i.value)), 4);
  const yMax = ticks[ticks.length - 1];
  const pw = W - M.l - M.r, ph = H - M.t - M.b;
  const base = M.t + ph;
  const slot = pw / items.length;
  const bw = Math.min(54, slot * 0.6);
  const yOf = v => base - (v / yMax) * ph;

  let g = '';
  ticks.forEach(t => {
    const y = yOf(t);
    g += `<line x1="${M.l}" x2="${W - M.r}" y1="${y}" y2="${y}" class="grid"/><text x="${M.l - 6}" y="${y + 4}" text-anchor="end">${t}</text>`;
  });
  items.forEach((it, i) => {
    const cx = M.l + slot * i + slot / 2, y = yOf(it.value);
    g += `<rect x="${cx - bw / 2}" y="${y}" width="${bw}" height="${base - y}" fill="${it.color}"/>` +
      `<text x="${cx}" y="${y - 5}" text-anchor="middle">${it.value}${percent ? ' (' + Math.round(it.value / total * 100) + '%)' : ''}</text>` +
      `<text x="${cx}" y="${base + 16}" text-anchor="middle" class="cat">${esc(it.label)}</text>`;
  });
  g += `<line x1="${M.l}" x2="${M.l}" y1="${M.t}" y2="${base}" class="axis"/><line x1="${M.l}" x2="${W - M.r}" y1="${base}" y2="${base}" class="axis"/>` +
    `<text transform="translate(13 ${M.t + ph / 2}) rotate(-90)" text-anchor="middle" class="ax-title">${esc(yLabel)}</text>`;

  return `<svg viewBox="0 0 ${W} ${H}" class="chart-svg" role="img">${g}</svg>`;
}
