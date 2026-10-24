import { esc } from '../../utils/esc.js';

/** Пустое значение «—» рисуем приглушённо. */
export function dim(v) {
  return v === '—' ? '<span class="dim">—</span>' : esc(v);
}
