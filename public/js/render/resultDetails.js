/**
 * Раскрывающаяся мини-таблица «Ожидалось / Факт» для одного файла.
 * @returns {{passed: boolean|null, html: string}}  passed === null, если эталон не задан
 */
export function resultDetails(exp, act) {
  const rows = [
    { label: 'Алерт', hint: '', e: exp && (exp.alert ? 'ДА' : 'НЕТ'), a: act.alert ? 'ДА' : 'НЕТ' },
    { label: 'IP выше порога', hint: 'из IP со сбоями', e: exp && (exp.ips + ' из ' + exp.ipsTotal), a: act.ips + ' из ' + act.ipsTotal },
    { label: 'Сбоев входа', hint: 'из всех попыток входа', e: exp && (exp.fails + ' из ' + exp.attempts), a: act.fails + ' из ' + act.attempts }
  ];

  let ok = 0;
  const body = rows.map(r => {
    const match = exp ? r.e === r.a : null;
    if (match) ok++;
    return '<tr><td>' + r.label + (r.hint ? '<small>' + r.hint + '</small>' : '') + '</td>' +
      '<td>' + (exp ? r.e : '—') + '</td><td><b>' + r.a + '</b></td>' +
      '<td class="' + (match === null ? '' : (match ? 'm-ok' : 'm-bad')) + '">' + (match === null ? '' : (match ? '✓' : '✗')) + '</td></tr>';
  }).join('');

  const caption = exp ? 'Показатели: ' + ok + ' из ' + rows.length + ' совпали' : 'Показатели';
  return {
    passed: exp ? ok === rows.length : null,
    html: '<details class="res"><summary>' + caption + '</summary>' +
      '<table class="mini"><thead><tr><th>Показатель</th><th>Ожидалось</th><th>Факт</th><th></th></tr></thead><tbody>' + body + '</tbody></table></details>'
  };
}
