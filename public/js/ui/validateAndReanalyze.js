import { store } from '../state.js';
import { render } from '../render/render.js';
import { showErrorModal } from './showErrorModal.js';

/** Проверяет поля «порог» и «окно»; при успехе применяет их и перерисовывает страницу. */
export function validateAndReanalyze() {
  const thRaw = document.getElementById('thresholdInput').value.trim();
  const winRaw = document.getElementById('windowInput').value.trim();

  if (!thRaw || !/^\d+$/.test(thRaw)) {
    showErrorModal('Некорректное "Пороговое число сбоев": поле должно содержать только целое положительное число.');
    return;
  }
  const thVal = parseInt(thRaw, 10);
  if (thVal < 1) {
    showErrorModal('Пороговое число сбоев должно быть не меньше 1.');
    return;
  }

  let parsedMinutes = 0;
  if (store.winMode === 'MIN') {
    if (!winRaw || !/^\d+$/.test(winRaw)) {
      showErrorModal('Некорректное "Временное окно": введите положительное целое число минут.');
      return;
    }
    parsedMinutes = parseInt(winRaw, 10);
  } else {
    const match = /^(\d{1,2}):(\d{2}):(\d{2})$/.exec(winRaw);
    if (!match) {
      showErrorModal('Неверный формат времени: используйте строгий формат ЧЧ:ММ:СС (например, 00:15:00).');
      return;
    }
    const h = parseInt(match[1], 10);
    const m = parseInt(match[2], 10);
    const s = parseInt(match[3], 10);
    if (m >= 60 || s >= 60) {
      showErrorModal('В формате ЧЧ:ММ:СС минуты и секунды не могут превышать 59.');
      return;
    }
    parsedMinutes = Math.ceil((h * 3600 + m * 60 + s) / 60);
  }

  if (parsedMinutes <= 0) {
    showErrorModal('Временное окно должно быть строго больше 0.');
    return;
  }

  const cur = store.data && store.data.files.find(x => x.fileName === store.currentFile);
  if (cur && cur.totalDurationMin > 0 && parsedMinutes > cur.totalDurationMin) {
    showErrorModal('Временное окно (' + parsedMinutes + ' мин) превышает общую длительность фиксации записей лога (' + cur.totalDurationMin + ' мин).');
    return;
  }

  store.threshold = thVal;
  store.windowMinutes = parsedMinutes;
  render();
}
