import { store } from '../state.js';
import { pad2 } from '../utils/pad2.js';
import { renderAllLogsTable } from '../render/renderAllLogsTable.js';
import { renderFlowTable } from '../traffic/renderFlowTable.js';
import { getCurrentPcap } from '../traffic/getCurrentPcap.js';

/**
 * Экспорт отчёта в PDF через печать браузера («Сохранить как PDF»).
 * Оформление печатной версии — в public/css/print.css.
 * @param {'file' | 'summary' | 'traffic'} scope  один файл, сводный отчёт или анализ трафика
 */
export function exportToPdf(scope) {
  const now = new Date();
  const nowStr = pad2(now.getDate()) + '.' + pad2(now.getMonth() + 1) + '.' + now.getFullYear() + ' ' +
    pad2(now.getHours()) + ':' + pad2(now.getMinutes()) + ':' + pad2(now.getSeconds());

  const metaEl = document.getElementById('printMetaDetails');
  const titleEl = document.getElementById('printReportTitle');
  const oldHeading = titleEl.textContent;
  const pcap = scope === 'traffic' ? getCurrentPcap() : null;
  if (scope === 'traffic') {
    if (!pcap) return;
    titleEl.textContent = 'ОТЧЁТ ПО АНАЛИЗУ СЕТЕВОГО ТРАФИКА';
    metaEl.textContent = 'Дата генерации: ' + nowStr + ' | Файл захвата: ' + pcap.fileName + ' | Пакетов: ' + pcap.totalPackets +
      ' | Потоков: ' + pcap.totalFlows + ' | Инцидентов: ' + pcap.incidents.length;
  } else if (scope === 'file') {
    metaEl.textContent = 'Дата генерации: ' + nowStr + ' | Объект: ' + store.currentFile + ' | Порог: ' + store.threshold +
      ' | Окно: ' + store.windowMinutes + ' мин. | ' + document.querySelector('#fileFilters .fcount').textContent;
  } else {
    metaEl.textContent = 'Дата генерации: ' + nowStr + ' | Сводный отчёт по всем журналам | Порог: ' + store.threshold +
      ' | Окно: ' + store.windowMinutes + ' мин. | ' + document.querySelector('#allFilters .fcount').textContent;
  }

  // в отчёт попадают все отфильтрованные строки, а не только первые 300
  const oldTitle = document.title;
  const oldLimit = store.allLimit;
  const oldTrafficLimit = store.trafficLimit;
  document.title = 'Отчёт ИБ — ' + (scope === 'file' ? store.currentFile : scope === 'traffic' ? 'трафик ' + pcap.fileName : 'сводный');
  if (scope === 'summary') {
    store.allLimit = Infinity;
    renderAllLogsTable();
  }
  if (scope === 'traffic') {
    store.trafficLimit = Infinity;
    renderFlowTable(pcap);
  }

  // раскрываем «Показатели» на время печати
  const dets = Array.from(document.querySelectorAll('details.res'));
  const wasOpen = dets.map(d => d.open);
  dets.forEach(d => { d.open = true; });

  window.onafterprint = () => {
    window.onafterprint = null;
    dets.forEach((d, i) => { d.open = wasOpen[i]; });
    document.title = oldTitle;
    titleEl.textContent = oldHeading;
    store.allLimit = oldLimit;
    store.trafficLimit = oldTrafficLimit;
    if (scope === 'summary') renderAllLogsTable();
    if (scope === 'traffic') renderFlowTable(pcap);
  };
  window.print();
}
