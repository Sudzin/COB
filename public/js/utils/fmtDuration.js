/** Секунды → "12.3 мс" или "4.52 с". */
export function fmtDuration(sec) {
  if (sec < 1) return (sec * 1000).toFixed(sec < 0.01 ? 2 : 1) + ' мс';
  return sec.toFixed(2) + ' с';
}
