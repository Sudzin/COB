const { normalizeFlowKey } = require('./normalizeFlowKey');

/**
 * Накапливает статистику по потокам (вместо вывода каждого пакета).
 * Ключ — пятёрка (IP_src, IP_dst, Port_src, Port_dst, Protocol), нормализованная так,
 * что A→B и B→A попадают в один поток. «Инициатор» — отправитель первого увиденного пакета.
 * @param {Iterable} packets  результат parsePacket
 * @returns {Map<string, object>}
 */
function aggregateFlows(packets) {
  const flows = new Map();

  for (const pkt of packets) {
    const key = normalizeFlowKey(pkt);
    let f = flows.get(key);
    if (!f) {
      f = {
        key,
        proto: pkt.proto,
        initiator: { ip: pkt.src, port: pkt.sport },
        responder: { ip: pkt.dst, port: pkt.dport },
        packets: 0,
        bytes: 0,
        start_time: pkt.ts,
        end_time: pkt.ts,
        max_size: 0,
        fwd: { packets: 0, bytes: 0 }, // инициатор → ответчик
        rev: { packets: 0, bytes: 0 }, // ответчик → инициатор
        syn_count: 0,
        ack_count: 0,
        rst_count: 0,
        fin_count: 0,
        psh_count: 0,
        icmp_types: {}
      };
      flows.set(key, f);
    }

    const forward = pkt.src === f.initiator.ip && pkt.sport === f.initiator.port;
    const dir = forward ? f.fwd : f.rev;
    dir.packets++;
    dir.bytes += pkt.len;

    f.packets++;
    f.bytes += pkt.len;
    if (pkt.ts < f.start_time) f.start_time = pkt.ts;
    if (pkt.ts > f.end_time) f.end_time = pkt.ts;
    if (pkt.len > f.max_size) f.max_size = pkt.len;

    if (pkt.flags.syn) f.syn_count++;
    if (pkt.flags.ack) f.ack_count++;
    if (pkt.flags.rst) f.rst_count++;
    if (pkt.flags.fin) f.fin_count++;
    if (pkt.flags.psh) f.psh_count++;

    if (pkt.icmpType !== null) {
      f.icmp_types[pkt.icmpType] = (f.icmp_types[pkt.icmpType] || 0) + 1;
    }
  }

  return flows;
}

module.exports = { aggregateFlows };
