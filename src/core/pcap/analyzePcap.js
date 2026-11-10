const { parsePcap } = require('./parsePcap');
const { parsePacket } = require('./parsePacket');
const { aggregateFlows } = require('./aggregateFlows');
const { computeFlowMetrics } = require('./computeFlowMetrics');
const { classifyFlows } = require('./classifyFlows');

const CATEGORIES = ['legit', 'scan', 'synflood', 'icmp'];

/** Равномерно прореживает массив до max элементов (для ответа API). */
function sample(arr, max) {
  if (arr.length <= max) return arr;
  const step = Math.ceil(arr.length / max);
  return arr.filter((_, i) => i % step === 0);
}

function serializeFlow(f) {
  const m = f.metrics;
  return {
    key: f.key,
    proto: f.proto,
    src: f.initiator.ip, sport: f.initiator.port,
    dst: f.responder.ip, dport: f.responder.port,
    packets: f.packets, bytes: f.bytes,
    start_time: f.start_time, end_time: f.end_time,
    fwd: f.fwd, rev: f.rev,
    syn_count: f.syn_count, ack_count: f.ack_count, rst_count: f.rst_count,
    fin_count: f.fin_count, psh_count: f.psh_count,
    max_size: f.max_size,
    duration: m.duration, pps: m.pps, bps: m.bps,
    syn_ratio: m.syn_ratio, avg_size: m.avg_size,
    category: f.category, reasons: f.reasons
  };
}

/**
 * Полный анализ одного .pcap: разбор → потоки → метрики → классификация → данные для графиков.
 * Знает только про Buffer, не про HTTP и файловую систему.
 */
function analyzePcap(buffer, fileName, cfg) {
  const { linkType, packets: rawPackets, truncated } = parsePcap(buffer);

  const packets = [];
  for (const raw of rawPackets) {
    const p = parsePacket(raw, linkType);
    if (p) packets.push(p);
  }

  const flowList = [...aggregateFlows(packets).values()];
  flowList.forEach(f => { f.metrics = computeFlowMetrics(f, cfg.MIN_DURATION_SEC); });
  const incidents = classifyFlows(flowList, cfg);

  // сводка по категориям (до обрезки списка потоков)
  const categories = {};
  CATEGORIES.forEach(c => { categories[c] = { flows: 0, packets: 0, bytes: 0 }; });
  flowList.forEach(f => {
    const c = categories[f.category];
    c.flows++; c.packets += f.packets; c.bytes += f.bytes;
  });

  // счётчики для диаграмм
  const protocols = { TCP: 0, UDP: 0, ICMP: 0 };
  const flags = { SYN: 0, ACK: 0, PSH: 0, RST: 0, FIN: 0 };
  flowList.forEach(f => {
    protocols[f.proto] += f.packets;
    flags.SYN += f.syn_count; flags.ACK += f.ack_count; flags.PSH += f.psh_count;
    flags.RST += f.rst_count; flags.FIN += f.fin_count;
  });

  const t0 = packets.length ? Math.min(...packets.map(p => p.ts)) : 0;
  const t1 = packets.length ? Math.max(...packets.map(p => p.ts)) : 0;
  const totalBytes = packets.reduce((acc, p) => acc + p.len, 0);

  const sizes = sample(packets.map(p => p.len), cfg.MAX_POINTS);
  const timeline = sample(packets, cfg.MAX_POINTS).map(p => ({ t: p.ts - t0, size: p.len, proto: p.proto }));

  const flows = flowList
    .slice()
    .sort((a, b) => b.packets - a.packets || b.bytes - a.bytes)
    .slice(0, cfg.MAX_FLOWS)
    .map(serializeFlow);

  return {
    fileName,
    status: 'OK',
    linkType,
    truncated,
    totalRecords: rawPackets.length,
    totalPackets: packets.length,
    ignoredPackets: rawPackets.length - packets.length,
    totalBytes,
    totalFlows: flowList.length,
    flowsTruncated: flowList.length > flows.length,
    t0,
    duration: t1 - t0,
    protocols,
    flags,
    categories,
    incidents,
    sizes,
    timeline,
    sampled: packets.length > cfg.MAX_POINTS,
    flows
  };
}

module.exports = { analyzePcap };
