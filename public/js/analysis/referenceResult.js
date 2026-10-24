import { EXPECTED_THRESHOLD } from '../constants.js';
import { failuresByIp } from './failuresByIp.js';

/** Фактический результат при эталонных параметрах (порог 5, весь файл). */
export function referenceResult(f) {
  let fails = 0;
  let accepted = 0;
  f.rows.forEach(r => {
    if (r.isFailure && r.ip !== '—') fails++;
    if (r.opStatus === 'Accepted') accepted++;
  });
  const map = failuresByIp(f.rows);
  const ipList = Object.keys(map);
  const ips = ipList.filter(ip => map[ip] > EXPECTED_THRESHOLD).length;
  return { alert: ips > 0, ips, ipsTotal: ipList.length, fails, attempts: fails + accepted };
}
