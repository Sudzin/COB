import { store } from '../state.js';
import { esc } from '../utils/esc.js';
import { failuresByIp } from '../analysis/failuresByIp.js';

/** Карточки метрик и таблица «Итоговая статистика активности IP» для выбранного файла. */
export function renderFileStatsAndSummary(cur, rows) {
  let failures = 0;
  let auths = 0;
  rows.forEach(r => {
    if (r.isFailure && r.ip !== '—') failures++;
    if (r.isSuccess) auths++;
  });
  const ipMap = failuresByIp(rows);
  const alerts = Object.keys(ipMap).filter(ip => ipMap[ip] > store.threshold);

  document.getElementById('fStatLines').textContent = cur.totalLines;
  document.getElementById('fStatFailures').textContent = failures;
  document.getElementById('fStatAuths').textContent = auths;
  document.getElementById('fStatAlerts').textContent = alerts.length;

  const sorted = Object.keys(ipMap).map(ip => [ip, ipMap[ip]]).sort((a, b) => b[1] - a[1]);
  let html = '';
  if (sorted.length === 0) {
    html = '<tr><td colspan="5" style="text-align:center; color:var(--muted); padding:1rem;">Сбоев входа в выбранном окне не зафиксировано</td></tr>';
  } else {
    sorted.forEach(([ip, count]) => {
      const isBreach = count > store.threshold;
      const warn = isBreach
        ? '<b style="color:var(--copper-deep);">[ПРЕДУПРЕЖДЕНИЕ]</b> Зафиксирован перебор паролей (Brute-force). Попыток: <b>' + count + ' &gt; ' + store.threshold + '</b>'
        : 'Активность в пределах допустимой нормы';
      html += '<tr><td class="mono">' + esc(ip) + '</td><td>' + count + '</td><td>' + store.threshold + '</td>' +
        '<td><span class="pill ' + (isBreach ? 'bad' : 'good') + '">' + (isBreach ? '[АТАК: 1]' : '[АТАК: 0]') + '</span></td>' +
        '<td>' + warn + '</td></tr>';
    });
  }
  document.getElementById('ipSummaryBody').innerHTML = html;
}
