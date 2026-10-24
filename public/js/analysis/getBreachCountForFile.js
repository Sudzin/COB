import { windowRows } from './windowRows.js';
import { failuresByIp } from './failuresByIp.js';

/** Сколько IP в файле превысили порог (попыток строго больше threshold). */
export function getBreachCountForFile(f, threshold, winMinutes) {
  if (f.status !== 'OK') return 0;
  const map = failuresByIp(windowRows(f, winMinutes));
  return Object.keys(map).filter(ip => map[ip] > threshold).length;
}
