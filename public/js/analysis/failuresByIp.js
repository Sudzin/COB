/** { "1.2.3.4": число неудачных попыток } */
export function failuresByIp(rows) {
  const counts = {};
  rows.forEach(r => {
    if (r.isFailure && r.ip !== '—') counts[r.ip] = (counts[r.ip] || 0) + 1;
  });
  return counts;
}
