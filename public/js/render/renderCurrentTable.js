import { store } from '../state.js';
import { windowRows } from '../analysis/windowRows.js';
import { bars } from '../filters/filterBars.js';
import { rowHtml } from './rowHtml.js';

/** Таблица журнала выбранного файла с учётом окна и фильтров. */
export function renderCurrentTable() {
  const cur = store.data && store.data.files.find(x => x.fileName === store.currentFile);
  if (!cur || !cur.rows) return;

  const rows = windowRows(cur, store.windowMinutes);
  const filtered = rows.filter(bars.file.match);
  bars.file.setCount(filtered.length, rows.length);

  const tb = document.getElementById('logTableBody');
  if (filtered.length === 0) {
    tb.innerHTML = '<tr><td colspan="9" style="text-align:center; padding:1.5rem; color:#8d9287;">Записей по заданным фильтрам не найдено</td></tr>';
    return;
  }
  tb.innerHTML = filtered.map(r => rowHtml(r, false)).join('');
}
