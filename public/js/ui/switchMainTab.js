import { store } from '../state.js';
import { renderAllLogsTable } from '../render/renderAllLogsTable.js';
import { renderTraffic } from '../traffic/renderTraffic.js';
import { loadTraffic } from '../api/loadTraffic.js';

const TABS = { file: 'tabContentFile', summary: 'tabContentSummary', traffic: 'tabContentTraffic' };
const BUTTONS = { file: 'tabBtnFile', summary: 'tabBtnSummary', traffic: 'tabBtnTraffic' };

/** Переключает вкладки: «Статистика по файлам» / «Общая статистика» / «Трафик». */
export function switchMainTab(tab) {
  store.activeTab = tab;
  Object.keys(TABS).forEach(name => {
    document.getElementById(BUTTONS[name]).classList.toggle('active', name === tab);
    document.getElementById(TABS[name]).style.display = name === tab ? 'block' : 'none';
  });
  // у вкладки «Трафик» своя панель выбора файла, список логов слева не нужен
  document.querySelector('.app-grid').classList.toggle('traffic-mode', tab === 'traffic');

  if (tab === 'summary') renderAllLogsTable();
  if (tab === 'traffic') {
    if (store.traffic) renderTraffic();
    else loadTraffic();
  }
}
