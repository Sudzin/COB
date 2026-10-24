import { store } from '../state.js';
import { getAllRows } from '../analysis/getAllRows.js';
import { bars } from '../filters/filterBars.js';
import { rowHtml } from './rowHtml.js';

/** Общий список журналов (все файлы) с фильтрами и кнопкой «Показать ещё». */
export function renderAllLogsTable() {
  if (!store.data || !store.data.files) return;

  const all = getAllRows(store.data.files);
  const filtered = all.filter(bars.all.match);
  bars.all.setCount(filtered.length, all.length);

  const tb = document.getElementById('allLogsTableBody');
  const more = document.getElementById('allMoreRow');

  if (filtered.length === 0) {
    tb.innerHTML = '<tr><td colspan="10" style="text-align:center; padding:1.5rem; color:#8d9287;">Записей не найдено</td></tr>';
    more.hidden = true;
    return;
  }

  const shown = filtered.slice(0, store.allLimit);
  tb.innerHTML = shown.map(r => rowHtml(r, true)).join('');
  more.hidden = filtered.length <= store.allLimit;
  document.getElementById('allMoreInfo').textContent = 'Показано ' + shown.length + ' из ' + filtered.length;
}
