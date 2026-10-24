import { store } from '../state.js';
import { windowRows } from '../analysis/windowRows.js';
import { bars } from '../filters/filterBars.js';
import { renderFileStatsAndSummary } from './renderFileStatsAndSummary.js';
import { renderCurrentTable } from './renderCurrentTable.js';

/** Вся правая вкладка «Статистика по файлам» для выбранного файла. */
export function renderFileDetails(cur) {
  document.getElementById('fileDetailBox').style.display = 'block';
  document.getElementById('selectedFileTitle').textContent = cur.fileName;
  document.getElementById('selectedFileBadge').textContent = '// ' + (cur.status === 'OK' ? 'УСПЕШНО' : cur.error);
  document.getElementById('winMaxHint').textContent = 'макс: ' + cur.totalDurationMin + ' мин';

  const rows = windowRows(cur, store.windowMinutes);
  // при смене файла фильтры сбрасываются
  if (store.barFile !== cur.fileName) {
    bars.file.reset(true);
    store.barFile = cur.fileName;
  }
  bars.file.setSource(rows);

  renderFileStatsAndSummary(cur, rows);
  renderCurrentTable();
}
