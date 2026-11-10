/** «Круглые» отметки оси от 0 до значения не меньше max. */
export function niceTicks(max, count = 5) {
  if (!(max > 0)) return [0, 1];
  const raw = max / count;
  const pow = 10 ** Math.floor(Math.log10(raw));
  const f = raw / pow;
  const step = (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * pow;
  const ticks = [];
  let i = 0;
  do { ticks.push(+(i * step).toFixed(10)); i++; } while (ticks[ticks.length - 1] < max);
  return ticks;
}
