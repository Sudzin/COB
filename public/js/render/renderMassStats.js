import { store } from '../state.js';
import { esc } from '../utils/esc.js';
import { EXPECTED } from '../config/expected.js';
import { getBreachCountForFile } from '../analysis/getBreachCountForFile.js';
import { referenceResult } from '../analysis/referenceResult.js';
import { resultDetails } from './resultDetails.js';

/** Вкладка «Общая статистика»: метрики и таблица результатов тестирования. */
export function renderMassStats() {
  let massLines = 0;
  let massFailures = 0;
  let massAlertFiles = 0;
  let html = '';

  store.data.files.forEach(f => {
    massLines += f.totalLines;
    f.rows.forEach(r => { if (r.isFailure) massFailures++; });
    if (getBreachCountForFile(f, store.threshold, store.windowMinutes) > 0) massAlertFiles++;

    if (f.status !== 'OK') {
      html += '<tr><td class="mono">' + esc(f.fileName) + '</td>' +
        '<td><span class="pill err">ОШИБКА</span></td>' +
        '<td><span class="pill err">Файл не прочитан</span></td>' +
        '<td>' + esc(f.error) + '. Программа продолжила работу.</td><td>—</td></tr>';
      return;
    }

    const exp = EXPECTED[f.fileName];
    const act = referenceResult(f);
    const det = resultDetails(exp, act);
    const verdict = det.passed === null
      ? '<span class="pill na">Эталон не задан</span>'
      : (det.passed ? '<span class="pill good">✓ Пройден</span>' : '<span class="pill bad">✗ Не пройден</span>');

    html += '<tr>' +
      '<td class="mono">' + esc(f.fileName) + '</td>' +
      '<td><span class="pill ' + (act.alert ? 'bad' : 'good') + '">' + (act.alert ? 'ДА' : 'НЕТ') + '</span></td>' +
      '<td>' + verdict + '</td>' +
      '<td>' + det.html + '</td>' +
      '<td>' + (exp ? esc(exp.note) : '—') + '</td>' +
      '</tr>';
  });
  document.getElementById('summaryTableBody').innerHTML = html;

  document.getElementById('mTotalFiles').textContent = store.data.files.length;
  document.getElementById('mTotalLines').textContent = massLines;
  document.getElementById('mTotalFailures').textContent = massFailures;
  document.getElementById('mFilesWithAlerts').textContent = massAlertFiles;
}
