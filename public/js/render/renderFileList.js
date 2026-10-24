import { store } from '../state.js';
import { esc } from '../utils/esc.js';
import { getBreachCountForFile } from '../analysis/getBreachCountForFile.js';

/**
 * Список файлов слева с бейджами «[АТАК: N]».
 * @param {Array} files
 * @param {(fileName: string) => void} onSelect  вызывается при клике на файл
 */
export function renderFileList(files, onSelect) {
  const container = document.getElementById('filesContainer');
  document.getElementById('filesCountLabel').textContent = '// ФАЙЛОВ: ' + files.length;
  container.innerHTML = '';

  files.forEach(f => {
    const div = document.createElement('div');
    div.className = 'file-item' + (store.currentFile === f.fileName ? ' active' : '');

    const breachCount = getBreachCountForFile(f, store.threshold, store.windowMinutes);
    let badgeHtml = '<span class="badge clean">[АТАК: 0]</span>';
    if (f.status !== 'OK') badgeHtml = '<span class="badge err">[ОШИБКА]</span>';
    else if (breachCount > 0) badgeHtml = '<span class="badge alert">[АТАК: ' + breachCount + ']</span>';

    div.innerHTML = '<span class="fname">' + esc(f.fileName) + '</span>' + badgeHtml;
    div.addEventListener('click', () => onSelect(f.fileName));
    container.appendChild(div);
  });
}
