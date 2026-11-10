import { noData } from './noData.js';

const W = 720, H = 320, M = { l: 64, r: 16, t: 16, b: 54 };

/** Гистограмма размеров пакетов, ось Y — логарифмическая. */
export function drawHistogram(sizes) {
  if (!sizes.length) return noData();

  let max = 0;
  for (const s of sizes) if (s > max) max = s;
  const BINS = 20;
  const step = Math.max(1, Math.ceil((max + 1) / BINS));
  const n = Math.floor(max / step) + 1;
  const counts = new Array(n).fill(0);
  for (const s of sizes) counts[Math.floor(s / step)]++;

  const maxC = Math.max(...counts);
  const yMin = 0.5;
  const yTop = Math.max(10, 10 ** Math.ceil(Math.log10(maxC)));
  const pw = W - M.l - M.r, ph = H - M.t - M.b;
  const base = M.t + ph;
  const yOf = c => M.t + ph * (1 - (Math.log(c) - Math.log(yMin)) / (Math.log(yTop) - Math.log(yMin)));
  const bw = pw / n;

  let g = '';
  for (let v = 1; v <= yTop; v *= 10) {
    const y = yOf(v);
    g += `<line x1="${M.l}" x2="${W - M.r}" y1="${y}" y2="${y}" class="grid"/>` +
      `<text x="${M.l - 6}" y="${y + 4}" text-anchor="end">${v}</text>`;
  }
  counts.forEach((c, i) => {
    if (!c) return;
    const x = M.l + i * bw, y = yOf(c);
    g += `<rect x="${x + 1}" y="${y}" width="${Math.max(1, bw - 2)}" height="${base - y}" fill="#c85a28"><title>${i * step}–${(i + 1) * step - 1} Б: ${c}</title></rect>`;
    if (bw > 20) g += `<text x="${x + bw / 2}" y="${y - 4}" text-anchor="middle">${c}</text>`;
  });
  const every = Math.ceil(n / 10);
  for (let i = 0; i < n; i += every) {
    g += `<text x="${M.l + i * bw}" y="${base + 16}" text-anchor="middle">${i * step}</text>`;
  }
  g += `<line x1="${M.l}" x2="${M.l}" y1="${M.t}" y2="${base}" class="axis"/><line x1="${M.l}" x2="${W - M.r}" y1="${base}" y2="${base}" class="axis"/>` +
    `<text x="${M.l + pw / 2}" y="${H - 8}" text-anchor="middle" class="ax-title">Размер пакета (байты)</text>` +
    `<text transform="translate(14 ${M.t + ph / 2}) rotate(-90)" text-anchor="middle" class="ax-title">Количество пакетов (log)</text>`;

  return `<svg viewBox="0 0 ${W} ${H}" class="chart-svg" role="img" aria-label="Гистограмма размеров пакетов">${g}</svg>`;
}
