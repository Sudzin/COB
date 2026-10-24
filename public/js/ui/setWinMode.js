import { store } from '../state.js';
import { pad2 } from '../utils/pad2.js';

/** Переключает формат ввода окна: минуты ↔ ЧЧ:ММ:СС, пересчитывая значение в поле. */
export function setWinMode(mode) {
  store.winMode = mode;
  document.getElementById('segMin').classList.toggle('on', mode === 'MIN');
  document.getElementById('segHms').classList.toggle('on', mode === 'HMS');

  const input = document.getElementById('windowInput');
  if (mode === 'HMS') {
    const t = store.windowMinutes * 60;
    input.value = pad2(Math.floor(t / 3600)) + ':' + pad2(Math.floor((t % 3600) / 60)) + ':' + pad2(t % 60);
  } else {
    input.value = String(store.windowMinutes);
  }
}
