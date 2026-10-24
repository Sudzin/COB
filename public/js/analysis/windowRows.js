import { getCutoff } from './getCutoff.js';

/** Строки файла, попавшие во временное окно (строки без метки времени остаются). */
export function windowRows(cur, winMinutes) {
  if (!cur || !cur.rows) return [];
  const cutoff = getCutoff(cur, winMinutes);
  if (cutoff === null) return cur.rows;
  return cur.rows.filter(r => r.ts === null || r.ts >= cutoff);
}
