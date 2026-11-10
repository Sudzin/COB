/** Помощники для тестов: собирают IPv4-пакеты и .pcap в памяти. */
const FLAG_BITS = { fin: 0x01, syn: 0x02, rst: 0x04, psh: 0x08, ack: 0x10 };

function ipv4Packet({ src, dst, proto = 'TCP', sport = 0, dport = 0, flags = [], icmpType = 8, payload = 0 }) {
  const l4 = proto === 'TCP' ? 20 : proto === 'UDP' ? 8 : 8;
  const total = 20 + l4 + payload;
  const b = Buffer.alloc(total);
  b[0] = 0x45;
  b.writeUInt16BE(total, 2);
  b[8] = 64;
  b[9] = { ICMP: 1, TCP: 6, UDP: 17 }[proto];
  src.split('.').forEach((x, i) => { b[12 + i] = Number(x); });
  dst.split('.').forEach((x, i) => { b[16 + i] = Number(x); });
  if (proto === 'ICMP') {
    b[20] = icmpType;
  } else {
    b.writeUInt16BE(sport, 20);
    b.writeUInt16BE(dport, 22);
    if (proto === 'TCP') {
      b[32] = 0x50;
      b[33] = flags.reduce((acc, f) => acc | FLAG_BITS[f], 0);
    }
  }
  return b;
}

/** frames: [{ts (сек), data: Buffer}] → Buffer формата pcap (LE, микросекунды). */
function buildPcap(frames, linkType = 101) {
  const header = Buffer.alloc(24);
  header.writeUInt32LE(0xa1b2c3d4, 0);
  header.writeUInt16LE(2, 4);
  header.writeUInt16LE(4, 6);
  header.writeUInt32LE(65535, 16);
  header.writeUInt32LE(linkType, 20);
  const parts = [header];
  for (const f of frames) {
    const rec = Buffer.alloc(16);
    rec.writeUInt32LE(Math.floor(f.ts), 0);
    rec.writeUInt32LE(Math.round((f.ts % 1) * 1e6), 4);
    rec.writeUInt32LE(f.data.length, 8);
    rec.writeUInt32LE(f.data.length, 12);
    parts.push(rec, f.data);
  }
  return Buffer.concat(parts);
}

module.exports = { ipv4Packet, buildPcap };
