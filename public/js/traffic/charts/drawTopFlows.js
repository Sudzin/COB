import { esc } from '../../utils/esc.js';
import { fmtNum } from '../../utils/fmtNum.js';
import { fmtDuration } from '../../utils/fmtDuration.js';
import { fmtEndpoint } from '../../utils/fmtEndpoint.js';
import { CATEGORY_COLOR } from '../../constants.js';
import { noData } from './noData.js';

const W = 720, ROW = 28, LABEL_W = 250, VALUE_W = 190;

/** Топ-10 самых активных потоков по числу пакетов; цвет — категория потока. */
export function drawTopFlows(flows) {
  const top = flows.slice().sort((a, b) => b.packets - a.packets || b.bytes - a.bytes).slice(0, 10);
  if (!top.length) return noData();

  const max = top[0].packets;
  const barX = LABEL_W + 10, barW = W - barX - VALUE_W;
  const H = top.length * ROW + 8;

  const rows = top.map((f, i) => {
    const y = 4 + i * ROW;
    let label = f.proto + ' ' + fmtEndpoint(f.proto, f.src, f.sport) + ' → ' + fmtEndpoint(f.proto, f.dst, f.dport);
    const full = label;
    if (label.length > 40) label = label.slice(0, 39) + '…';
    const w = Math.max(2, (f.packets / max) * barW);
    return `<text x="${LABEL_W}" y="${y + 16}" text-anchor="end"><title>${esc(full)}</title>${esc(label)}</text>` +
      `<rect x="${barX}" y="${y + 3}" width="${w}" height="${ROW - 8}" fill="${CATEGORY_COLOR[f.category]}"/>` +
      `<text x="${W - 4}" y="${y + 16}" text-anchor="end">${fmtNum(f.packets)} пак · ${fmtNum(f.bytes)} Б · ${fmtDuration(f.duration)}</text>`;
  }).join('');

  return `<svg viewBox="0 0 ${W} ${H}" class="chart-svg chart-svg--top" role="img" aria-label="Топ-10 потоков">${rows}</svg>`;
}
