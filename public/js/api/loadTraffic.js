import { store } from '../state.js';
import { renderTraffic } from '../traffic/renderTraffic.js';
import { showErrorModal } from '../ui/showErrorModal.js';

/** Запрашивает у сервера анализ всех .pcap и рисует вкладку «Трафик». */
export async function loadTraffic() {
  try {
    const res = await fetch('/api/traffic');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    store.traffic = await res.json();
    renderTraffic();
  } catch (e) {
    showErrorModal('Не удалось получить данные о трафике (API недоступно).');
  }
}
