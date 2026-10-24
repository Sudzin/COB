import { createFilterBar } from './createFilterBar.js';
import { F_IP, F_USER, F_SERVICE, F_HOST, F_FILE } from './filterFields.js';

/**
 * Реестр панелей фильтров. Модули отрисовки берут готовые панели отсюда (bars.file / bars.all),
 * а main.js создаёт их через initFilterBars — так нет циклических импортов.
 */
export const bars = { file: null, all: null };

export function initFilterBars({ onFileChange, onAllChange, onExport }) {
  bars.file = createFilterBar(
    document.getElementById('fileFilters'),
    [F_IP, F_USER, F_SERVICE, F_HOST],
    { onChange: onFileChange, onExport: () => onExport('file') }
  );
  bars.all = createFilterBar(
    document.getElementById('allFilters'),
    [F_FILE, F_IP, F_USER, F_SERVICE, F_HOST],
    { onChange: onAllChange, onExport: () => onExport('summary') }
  );
}
