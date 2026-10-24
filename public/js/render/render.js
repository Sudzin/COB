import { store } from '../state.js';
import { esc } from '../utils/esc.js';
import { getAllRows } from '../analysis/getAllRows.js';
import { bars } from '../filters/filterBars.js';
import { switchMainTab } from '../ui/switchMainTab.js';
import { renderFileList } from './renderFileList.js';
import { renderFileDetails } from './renderFileDetails.js';
import { renderMassStats } from './renderMassStats.js';
import { renderAllLogsTable } from './renderAllLogsTable.js';

/** Главная перерисовка: вызывает остальные render-модули по порядку. */
export function render() {
  const data = store.data;
  if (!data) return;

  if (data.status !== 'SUCCESS') {
    document.getElementById('filesContainer').innerHTML =
      '<div class="empty">' + esc(data.error || 'Нет данных') + '</div>';
    return;
  }

  // файл по умолчанию выбираем до отрисовки списка, чтобы он сразу подсветился
  if (!store.currentFile && data.files.length > 0) store.currentFile = data.files[0].fileName;

  renderFileList(data.files, fileName => {
    store.currentFile = fileName;
    switchMainTab('file');
    render();
  });

  const cur = data.files.find(x => x.fileName === store.currentFile);
  if (cur) renderFileDetails(cur);

  renderMassStats();

  bars.all.setSource(getAllRows(data.files));
  if (store.activeTab === 'summary') renderAllLogsTable();
}
