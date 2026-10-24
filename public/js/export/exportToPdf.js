import { store } from '../state.js';
import { pad2 } from '../utils/pad2.js';
import { renderAllLogsTable } from '../render/renderAllLogsTable.js';

/**
 * Экспорт отчёта в PDF через печать браузера («Сохранить как PDF»).
 * Оформление печатной версии — в public/css/print.css.
 * @param {'file' | 'summary'} scope  один файл или сводный отчёт
 */
export function exportToPdf(scope) {
  const now = new Date();
  const nowStr = pad2(now.getDate()) + '.' + pad2(now.getMonth() + 1) + '.' + now.getFullYear() + ' ' +
    pad2(now.getHours()) + ':' + pad2(now.getMinutes()) + ':' + pad2(now.getSeconds());

  const metaEl = document.getElementById('printMetaDetails');
  if (scope === 'file') {
    metaEl.textContent = 'Дата генерации: ' + nowStr + ' | Объект: ' + store.currentFile + ' | Порог: ' + store.threshold +
      ' | Окно: ' + store.windowMinutes + ' мин. | ' + document.querySelector('#fileFilters .fcount').textContent;
  } else {
    metaEl.textContent = 'Дата генерации: ' + nowStr + ' | Сводный отчёт по всем журналам | Порог: ' + store.threshold +
      ' | Окно: ' + store.windowMinutes + ' мин. | ' + document.querySelector('#allFilters .fcount').textContent;
  }

  // в отчёт попадают все отфильтрованные строки, а не только первые 300
  const oldTitle = document.title;
  const oldLimit = store.allLimit;
  document.title = 'Отчёт ИБ — ' + (scope === 'file' ? store.currentFile : 'сводный');
  if (scope === 'summary') {
    store.allLimit = Infinity;
    renderAllLogsTable();
  }

  // раскрываем «Показатели» на время печати
  const dets = Array.from(document.querySelectorAll('details.res'));
  const wasOpen = dets.map(d => d.open);
  dets.forEach(d => { d.open = true; });

  window.onafterprint = () => {
    window.onafterprint = null;
    dets.forEach((d, i) => { d.open = wasOpen[i]; });
    document.title = oldTitle;
    store.allLimit = oldLimit;
    if (scope === 'summary') renderAllLogsTable();
  };
  window.print();
}
