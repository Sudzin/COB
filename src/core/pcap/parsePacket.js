const IP_PROTO = { 1: 'ICMP', 6: 'TCP', 17: 'UDP' };

/** Находит начало IPv4-заголовка в кадре, учитывая тип канального уровня. -1 — это не IPv4. */
function findIpOffset(data, linkType) {
  switch (linkType) {
    case 1: { // Ethernet (+ один тег VLAN)
      if (data.length < 14) return -1;
      let type = data.readUInt16BE(12);
      let off = 14;
      if (type === 0x8100 && data.length >= 18) { type = data.readUInt16BE(16); off = 18; }
      return type === 0x0800 ? off : -1;
    }
    case 0: // BSD loopback (Npcap Loopback): 4 байта семейства адресов
      if (data.length < 4) return -1;
      return data[0] === 2 || data[3] === 2 ? 4 : -1;
    case 101: // Raw IP (v4 или v6 — различаем по версии)
    case 228: // Raw IPv4
      return data.length >= 1 && data[0] >> 4 === 4 ? 0 : -1;
    case 113: // Linux cooked capture
      if (data.length < 16) return -1;
      return data.readUInt16BE(14) === 0x0800 ? 16 : -1;
    default:
      return -1;
  }
}

/**
 * Разбирает кадр. Возвращает null, если в нём нет IPv4 + TCP/UDP/ICMP (такие пакеты игнорируются).
 * @returns {null | {ts, len, src, dst, proto, sport, dport, flags, icmpType, icmpCode}}
 */
function parsePacket(raw, linkType) {
  const data = raw.data;
  const ipOff = findIpOffset(data, linkType);
  if (ipOff < 0 || data.length < ipOff + 20) return null;

  const ihl = (data[ipOff] & 0x0f) * 4;
  if (ihl < 20 || data.length < ipOff + ihl) return null;

  const fragOffset = data.readUInt16BE(ipOff + 6) & 0x1fff;
  if (fragOffset !== 0) return null; // не первый фрагмент: заголовка L4 в нём нет

  const proto = IP_PROTO[data[ipOff + 9]];
  if (!proto) return null;

  const l4 = ipOff + ihl;
  const pkt = {
    ts: raw.ts,
    len: raw.origLen,
    src: ipToString(data, ipOff + 12),
    dst: ipToString(data, ipOff + 16),
    proto,
    sport: 0,
    dport: 0,
    flags: { syn: false, ack: false, rst: false, fin: false, psh: false },
    icmpType: null,
    icmpCode: null
  };

  if (proto === 'ICMP') {
    if (data.length < l4 + 2) return null;
    pkt.icmpType = data[l4];
    pkt.icmpCode = data[l4 + 1];
    return pkt;
  }

  if (data.length < l4 + 4) return null;
  pkt.sport = data.readUInt16BE(l4);
  pkt.dport = data.readUInt16BE(l4 + 2);

  if (proto === 'TCP' && data.length >= l4 + 14) {
    const f = data[l4 + 13];
    pkt.flags = {
      fin: !!(f & 0x01),
      syn: !!(f & 0x02),
      rst: !!(f & 0x04),
      psh: !!(f & 0x08),
      ack: !!(f & 0x10)
    };
  }
  return pkt;
}

function ipToString(buf, off) {
  return buf[off] + '.' + buf[off + 1] + '.' + buf[off + 2] + '.' + buf[off + 3];
}

module.exports = { parsePacket };
