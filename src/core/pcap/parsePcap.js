/**
 * Разбирает содержимое .pcap (классический формат libpcap) в список «сырых» пакетов.
 * @returns {{linkType:number, packets:{ts:number, origLen:number, data:Buffer}[], truncated:boolean}}
 * @throws Error с полем code: ERR_NOT_PCAP | ERR_PCAPNG
 */
function parsePcap(buffer) {
  if (buffer.length < 24) throw makeError('ERR_NOT_PCAP', 'Файл слишком короткий для .pcap');

  const magicLE = buffer.readUInt32LE(0);
  if (magicLE === 0x0a0d0d0a) {
    throw makeError('ERR_PCAPNG', 'Формат pcapng не поддерживается: сохраните как .pcap (Wireshark: «Сохранить как» → pcap)');
  }

  let le, nano;
  if (magicLE === 0xa1b2c3d4) { le = true; nano = false; }
  else if (magicLE === 0xa1b23c4d) { le = true; nano = true; }
  else if (magicLE === 0xd4c3b2a1) { le = false; nano = false; }
  else if (magicLE === 0x4d3cb2a1) { le = false; nano = true; }
  else throw makeError('ERR_NOT_PCAP', 'Неизвестная сигнатура: это не .pcap');

  const u32 = off => (le ? buffer.readUInt32LE(off) : buffer.readUInt32BE(off));
  const linkType = u32(20) & 0x0fffffff; // старшие биты — флаги FCS, нам не нужны

  const packets = [];
  let off = 24;
  let truncated = false;
  while (off + 16 <= buffer.length) {
    const sec = u32(off);
    const frac = u32(off + 4);
    const capLen = u32(off + 8);
    const origLen = u32(off + 12);
    off += 16;
    if (off + capLen > buffer.length) { truncated = true; break; }
    packets.push({
      ts: sec + frac / (nano ? 1e9 : 1e6),
      origLen,
      data: buffer.subarray(off, off + capLen)
    });
    off += capLen;
  }
  if (off < buffer.length && !truncated) truncated = true; // хвост короче заголовка записи

  return { linkType, packets, truncated };
}

function makeError(code, message) {
  const e = new Error(message);
  e.code = code;
  return e;
}

module.exports = { parsePcap };
