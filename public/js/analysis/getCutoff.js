/** Граница окна: время последней записи минус N минут. null — окно не ограничивает. */
export function getCutoff(cur, winMinutes) {
  if (!cur.maxTime || !isFinite(winMinutes)) return null;
  return Date.parse(cur.maxTime) - winMinutes * 60000;
}
