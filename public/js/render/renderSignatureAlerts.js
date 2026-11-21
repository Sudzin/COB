import { esc } from '../utils/esc.js';
import { fmtNum } from '../utils/fmtNum.js';

const SEVERITY_RANK = { LOW: 1, MEDIUM: 2, HIGH: 3 };

function drawAlerts(cur, minSeverity) {
  const alerts = cur.alerts || [];
  const minRank = SEVERITY_RANK[minSeverity] || 1;
  const visible = alerts.filter(a => (SEVERITY_RANK[a.severity] || 0) >= minRank);

  const counter = document.getElementById('tAlerts');
  if (counter) counter.textContent = fmtNum(alerts.length);

  const box = document.getElementById('trafficAlerts');
  if (!box) return;

  if (!alerts.length) {
    box.innerHTML = '<div class="empty">Сигнатурные алерты не сработали.</div>';
    return;
  }
  if (!visible.length) {
    box.innerHTML = '<div class="empty">Нет алертов уровня ' + esc(minSeverity) + ' и выше (всего: ' + fmtNum(alerts.length) + ').</div>';
    return;
  }

  box.innerHTML = visible.map(a => {
    const sev = String(a.severity || 'LOW').toLowerCase();
    return '<div class="incident inc-sig-' + sev + '">' +
      '<div class="inc-head">' +
        '<span class="pill sev-' + sev + '">' + esc(a.severity) + '</span>' +
        '<b>' + esc(a.signature_name) + '</b>' +
        '<span class="mono">' + esc(a.src_ip) + ' → ' + esc(a.dst_ip) + '</span>' +
      '</div>' +
      '<p>' + esc(a.details) + '</p>' +
      '<div class="inc-meta">Время: ' + esc(a.timestamp) + '</div>' +
    '</div>';
  }).join('');
}

/** Отрисовка блока «Сигнатурные алерты» с фильтром по severity. */
export function renderSignatureAlerts(cur) {
  const select = document.getElementById('severityFilter');
  const minSeverity = select ? select.value : 'LOW';
  drawAlerts(cur, minSeverity);
  if (select) {
    select.onchange = () => drawAlerts(cur, select.value);
  }
}
