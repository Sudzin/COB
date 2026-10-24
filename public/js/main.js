/**
 * Точка входа фронтенда: создаёт панели фильтров, навешивает обработчики, загружает данные.
 */
import { store } from './state.js';
import { PAGE_STEP } from './constants.js';
import { initFilterBars } from './filters/filterBars.js';
import { renderCurrentTable } from './render/renderCurrentTable.js';
import { renderAllLogsTable } from './render/renderAllLogsTable.js';
import { exportToPdf } from './export/exportToPdf.js';
import { switchMainTab } from './ui/switchMainTab.js';
import { setWinMode } from './ui/setWinMode.js';
import { validateAndReanalyze } from './ui/validateAndReanalyze.js';
import { closeErrorModal } from './ui/closeErrorModal.js';
import { showMoreAll } from './ui/showMoreAll.js';
import { loadData } from './api/loadData.js';

initFilterBars({
  onFileChange: renderCurrentTable,
  onAllChange: () => {
    store.allLimit = PAGE_STEP;
    renderAllLogsTable();
  },
  onExport: exportToPdf
});

const on = (id, event, handler) => document.getElementById(id).addEventListener(event, handler);

on('tabBtnFile', 'click', () => switchMainTab('file'));
on('tabBtnSummary', 'click', () => switchMainTab('summary'));
on('segMin', 'click', () => setWinMode('MIN'));
on('segHms', 'click', () => setWinMode('HMS'));
on('applyBtn', 'click', validateAndReanalyze);
on('errModalClose', 'click', closeErrorModal);
on('showMoreBtn', 'click', showMoreAll);

['thresholdInput', 'windowInput'].forEach(id => {
  on(id, 'keydown', e => {
    if (e.key === 'Enter') validateAndReanalyze();
  });
});

loadData();
