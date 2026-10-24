import { store } from '../state.js';
import { renderAllLogsTable } from '../render/renderAllLogsTable.js';

/** Переключает вкладки «Статистика по файлам» / «Общая статистика». */
export function switchMainTab(tab) {
  store.activeTab = tab;
  document.getElementById('tabBtnFile').classList.toggle('active', tab === 'file');
  document.getElementById('tabBtnSummary').classList.toggle('active', tab === 'summary');
  document.getElementById('tabContentFile').style.display = tab === 'file' ? 'block' : 'none';
  document.getElementById('tabContentSummary').style.display = tab === 'summary' ? 'block' : 'none';
  if (tab === 'summary') renderAllLogsTable();
}
