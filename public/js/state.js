import { PAGE_STEP } from './constants.js';

/**
 * Единое хранилище состояния приложения.
 * Объект, а не отдельные переменные: импортируемые `let` из других модулей переприсвоить нельзя.
 */
export const store = {
  data: null,                 // ответ /api/scan
  currentFile: null,          // выбранный файл
  activeTab: 'file',          // 'file' | 'summary'
  threshold: 5,               // пороговое число сбоев
  windowMinutes: 60,          // временное окно (в минутах)
  winMode: 'MIN',             // формат ввода окна: 'MIN' | 'HMS'
  barFile: null,              // для какого файла сейчас настроена панель фильтров
  allLimit: PAGE_STEP         // сколько строк показано в общем списке
};
