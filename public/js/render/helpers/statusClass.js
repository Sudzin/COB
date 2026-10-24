/** CSS-класс плашки статуса операции. */
export function statusClass(s) {
  if (s === 'Invalid') return 'st-invalid';
  if (s === 'Failed') return 'st-failed';
  if (s === 'Accepted') return 'st-accepted';
  if (s === 'Session') return 'st-session';
  return 'st-info';
}
