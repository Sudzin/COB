import { niceTicks } from '../../utils/niceTicks.js';
import { PROTO_COLOR } from '../../constants.js';
import { noData } from './noData.js';

const W = 720, H = 340, M = { l: 64, r: 16, t: 28, b: 54 };

/** Таймлайн: по X — время от начала захвата, по Y — размер пакета; цвет — протокол. */
export function drawScatter(points, duration) {
  if (!points.length) return noData();

  const useMs = duration < 1;
  const k = useMs ? 1000 : 1;
  const unit = useMs ? 'мс' : 'с';
  let maxT = 0, maxS = 0;
  for (const p of points) { if (p.t > maxT) maxT = p.t; if (p.size > maxS) maxS = p.size; }

  const xt = niceTicks(maxT * k || 1, 6), yt = niceTicks(maxS * 1.05, 5);
  const xMax = xt[xt.length - 1], yMax = yt[yt.length - 1];
  const pw = W - M.l - M.r, ph = H - M.t - M.b, base = M.t + ph;
  const xOf = v => M.l + (v / xMax) * pw, yOf = v => base - (v / yMax) * ph;

  let g = '';
  yt.forEach(t => { g += `<line x1="${M.l}" x2="${W - M.r}" y1="${yOf(t)}" y2="${yOf(t)}" class="grid"/><text x="${M.l - 6}" y="${yOf(t) + 4}" text-anchor="end">${t}</text>`; });
  xt.forEach(t => { g += `<text x="${xOf(t)}" y="${base + 16}" text-anchor="middle">${t}</text>`; });
  for (const p of points) {
    g += `<circle cx="${xOf(p.t * k).toFixed(1)}" cy="${yOf(p.size).toFixed(1)}" r="2.4" fill="${PROTO_COLOR[p.proto] || '#575952'}" fill-opacity=".6"/>`;
  }
  g += `<line x1="${M.l}" x2="${M.l}" y1="${M.t}" y2="${base}" class="axis"/><line x1="${M.l}" x2="${W - M.r}" y1="${base}" y2="${base}" class="axis"/>` +
    `<text x="${M.l + pw / 2}" y="${H - 8}" text-anchor="middle" class="ax-title">Время от начала захвата (${unit})</text>` +
    `<text transform="translate(14 ${M.t + ph / 2}) rotate(-90)" text-anchor="middle" class="ax-title">Размер пакета (байты)</text>`;

  const present = [...new Set(points.map(p => p.proto))];
  present.forEach((proto, i) => {
    const x = W - M.r - 70 * (present.length - i);
    g += `<circle cx="${x}" cy="12" r="4" fill="${PROTO_COLOR[proto] || '#575952'}"/><text x="${x + 8}" y="16">${proto}</text>`;
  });

  return `<svg viewBox="0 0 ${W} ${H}" class="chart-svg" role="img" aria-label="Таймлайн активности">${g}</svg>`;
}
