/** Скорость для таблицы: null (мало данных) → "—", большие числа — с приставкой k/M. */
export function fmtRate(v) {
  if (v === null || v === undefined) return '—';
  if (v >= 1e6) return (v / 1e6).toFixed(1) + ' M';
  if (v >= 1e3) return (v / 1e3).toFixed(1) + ' k';
  return v.toFixed(1);
}
