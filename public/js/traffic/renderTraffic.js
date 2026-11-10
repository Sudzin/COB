import { store } from '../state.js';
import { esc } from '../utils/esc.js';
import { getCurrentPcap } from './getCurrentPcap.js';
import { renderTrafficSummary } from './renderTrafficSummary.js';
import { renderTrafficCharts } from './renderTrafficCharts.js';
import { renderFlowTable } from './renderFlowTable.js';

/** Главная отрисовка вкладки «Трафик»: выбор файла, сводка, графики, таблица потоков. */
export function renderTraffic() {
  const data = store.traffic;
  if (!data) return;

  const emptyEl = document.getElementById('trafficEmpty');
  const bodyEl = document.getElementById('trafficBody');
  const select = document.getElementById('pcapSelect');
  const showEmpty = text => {
    emptyEl.textContent = text;
    emptyEl.style.display = 'block';
    bodyEl.style.display = 'none';
  };

  if (data.status !== 'SUCCESS') {
    select.innerHTML = '';
    document.getElementById('trafficFileTag').textContent = '// ФАЙЛОВ: 0';
    return showEmpty(data.error || 'Нет данных');
  }

  select.innerHTML = data.files
    .map(f => '<option value="' + esc(f.fileName) + '">' + esc(f.fileName) + (f.status === 'OK' ? '' : ' (ошибка)') + '</option>')
    .join('');
  if (!data.files.some(f => f.fileName === store.currentPcap)) {
    const firstOk = data.files.find(f => f.status === 'OK') || data.files[0];
    store.currentPcap = firstOk.fileName;
  }
  select.value = store.currentPcap;
  document.getElementById('trafficFileTag').textContent = '// ФАЙЛОВ: ' + data.files.length;

  const cur = getCurrentPcap();
  if (!cur) {
    const bad = data.files.find(f => f.fileName === store.currentPcap);
    return showEmpty('Файл не разобран: ' + (bad && bad.error ? bad.error : 'неизвестная ошибка'));
  }

  emptyEl.style.display = 'none';
  bodyEl.style.display = 'block';
  renderTrafficSummary(cur);
  renderTrafficCharts(cur);
  renderFlowTable(cur);
}
