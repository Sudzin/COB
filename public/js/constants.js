// Сколько строк добавляет кнопка «Показать ещё» в общем списке
export const PAGE_STEP = 300;

// Порог, при котором считается «эталонный» результат в таблице тестирования
export const EXPECTED_THRESHOLD = 5;

export const STATUS_LABEL = {
  Failed: 'Failed',
  Invalid: 'Invalid',
  Accepted: 'Accepted',
  Session: 'Session',
  INFO: 'Прочее'
};

export const STATUS_ORDER = ['Failed', 'Invalid', 'Accepted', 'Session', 'INFO'];

// ---- ЛР №2: анализ трафика ----
export const TRAFFIC_PAGE_STEP = 100;

export const CATEGORY_ORDER = ['legit', 'scan', 'synflood', 'icmp'];
export const CATEGORY_LABEL = {
  legit: 'Легитимный',
  scan: 'Сканирование портов',
  synflood: 'SYN-флуд (DoS)',
  icmp: 'Аномалия ICMP'
};
export const CATEGORY_COLOR = { legit: '#3f6168', scan: '#c85a28', synflood: '#ab1f1f', icmp: '#6b4c9a' };
export const PROTO_COLOR = { TCP: '#c85a28', UDP: '#3f6168', ICMP: '#6b4c9a' };
