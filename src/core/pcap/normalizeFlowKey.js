/** "192.168.1.10" → число, чтобы упорядочивать адреса. */
function ipToNumber(ip) {
  return ip.split('.').reduce((acc, part) => acc * 256 + Number(part), 0);
}

/**
 * Ключ потока для СИММЕТРИЧНОГО анализа: пакеты A→B и B→A дают один и тот же ключ.
 * Концы (ip, порт) упорядочиваются, протокол входит в ключ.
 * @returns {string} например "TCP|10.0.0.1:443|192.168.1.5:50000"
 */
function normalizeFlowKey(pkt) {
  const a = { ip: pkt.src, port: pkt.sport };
  const b = { ip: pkt.dst, port: pkt.dport };
  const aFirst = ipToNumber(a.ip) < ipToNumber(b.ip) ||
    (a.ip === b.ip && a.port <= b.port);
  const [lo, hi] = aFirst ? [a, b] : [b, a];
  return `${pkt.proto}|${lo.ip}:${lo.port}|${hi.ip}:${hi.port}`;
}

module.exports = { normalizeFlowKey, ipToNumber };
