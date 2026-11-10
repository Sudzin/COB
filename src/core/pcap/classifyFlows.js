const ICMP_TYPE_NAMES = {
  0: 'Echo Reply', 3: 'Destination Unreachable', 4: 'Source Quench', 5: 'Redirect',
  8: 'Echo Request', 9: 'Router Advertisement', 11: 'Time Exceeded', 13: 'Timestamp', 17: 'Address Mask'
};

const isBroadcast = ip => ip === '255.255.255.255' || ip.endsWith('.255');

function groupBy(items, keyFn) {
  const map = new Map();
  for (const it of items) {
    const k = keyFn(it);
    if (!map.has(k)) map.set(k, []);
    map.get(k).push(it);
  }
  return map;
}

function sum(items, field) {
  return items.reduce((acc, it) => acc + it[field], 0);
}

function span(items) {
  return {
    start_time: Math.min(...items.map(f => f.start_time)),
    end_time: Math.max(...items.map(f => f.end_time))
  };
}

/**
 * Эвристическая классификация потоков. Каждому потоку ставит category и reasons:
 *   legit | scan | synflood | icmp
 * и возвращает список инцидентов (по одному на найденную атаку/аномалию).
 * Пороги — в config.TRAFFIC.
 */
function classifyFlows(flows, cfg) {
  const incidents = [];
  flows.forEach(f => { f.category = 'legit'; f.reasons = []; });

  // 1. Сканирование портов: один источник → один узел, много РАЗНЫХ портов, на каждый 1–2 пакета без ACK
  const probes = flows.filter(f =>
    f.proto === 'TCP' && f.syn_count > 0 && f.ack_count === 0 && f.packets <= cfg.SCAN_MAX_PKTS_PER_PORT);
  for (const group of groupBy(probes, f => f.initiator.ip + '>' + f.responder.ip).values()) {
    const ports = [...new Set(group.map(f => f.responder.port))].sort((a, b) => a - b);
    if (ports.length < cfg.SCAN_MIN_PORTS) continue;
    const first = group[0];
    const sequential = ports[ports.length - 1] - ports[0] + 1 === ports.length;
    group.forEach(f => {
      f.category = 'scan';
      f.reasons = ['Один SYN на порт, всего ' + ports.length + ' портов узла ' + first.responder.ip];
    });
    incidents.push({
      type: 'scan',
      title: 'Сканирование портов',
      src: first.initiator.ip,
      dst: first.responder.ip,
      description: `${first.initiator.ip} отправил SYN на ${ports.length} разных портов узла ${first.responder.ip} ` +
        `(${ports[0]}–${ports[ports.length - 1]}${sequential ? ', подряд' : ''}), по ${Math.max(...group.map(f => f.packets))} пакету на порт, без завершения соединений.`,
      flows: group.length,
      packets: sum(group, 'packets'),
      ...span(group)
    });
  }

  // 2. SYN-флуд: много SYN без ACK на один порт (от многих источников или просто очень много)
  const halfOpen = flows.filter(f =>
    f.category === 'legit' && f.proto === 'TCP' && f.syn_count > 0 && f.ack_count === 0);
  for (const group of groupBy(halfOpen, f => f.responder.ip + ':' + f.responder.port).values()) {
    const sources = [...new Set(group.map(f => f.initiator.ip))];
    const synPackets = sum(group, 'syn_count');
    if (sources.length < cfg.FLOOD_MIN_SOURCES && synPackets < cfg.FLOOD_MIN_PACKETS) continue;
    const first = group[0];
    const t = span(group);
    group.forEach(f => {
      f.category = 'synflood';
      f.reasons = ['SYN без ACK на ' + first.responder.ip + ':' + first.responder.port + ', источников: ' + sources.length];
    });
    incidents.push({
      type: 'synflood',
      title: 'SYN-флуд (DoS)',
      src: sources.length > 1 ? sources.length + ' источников' : sources[0],
      dst: first.responder.ip + ':' + first.responder.port,
      sources: sources.slice(0, 5),
      sources_count: sources.length,
      description: `${synPackets} SYN-пакетов без единого ACK на ${first.responder.ip}:${first.responder.port} ` +
        `от ${sources.length} источник(ов); соединения не завершаются.`,
      flows: group.length,
      packets: sum(group, 'packets'),
      ...t
    });
  }

  // 3. Аномалии ICMP
  for (const f of flows.filter(x => x.proto === 'ICMP')) {
    const reasons = [];
    const types = Object.keys(f.icmp_types).map(Number);
    if ((isBroadcast(f.initiator.ip) || isBroadcast(f.responder.ip)) && f.icmp_types[8]) {
      reasons.push('echo-запросы на broadcast-адрес (возможен smurf-приём)');
    }
    if (f.max_size > cfg.ICMP_BIG_SIZE) {
      reasons.push('необычно крупные пакеты: до ' + f.max_size + ' байт');
    }
    const odd = types.filter(t => !cfg.ICMP_NORMAL_TYPES.includes(t));
    if (odd.length) {
      reasons.push('нестандартные типы: ' + odd.map(t => t + ' (' + (ICMP_TYPE_NAMES[t] || '?') + ')').join(', '));
    }
    const duration = f.end_time - f.start_time;
    if (f.packets >= cfg.ICMP_FLOOD_PACKETS && duration >= cfg.MIN_DURATION_SEC && f.packets / duration >= cfg.ICMP_FLOOD_PPS) {
      reasons.push('высокая частота: ' + Math.round(f.packets / duration) + ' пакетов/с');
    }
    if (!reasons.length) continue;
    f.category = 'icmp';
    f.reasons = reasons;
    incidents.push({
      type: 'icmp',
      title: 'Аномалия ICMP',
      src: f.initiator.ip,
      dst: f.responder.ip,
      description: f.initiator.ip + ' → ' + f.responder.ip + ': ' + reasons.join('; ') + '. Пакетов: ' + f.packets + '.',
      flows: 1,
      packets: f.packets,
      start_time: f.start_time,
      end_time: f.end_time
    });
  }

  return incidents;
}

module.exports = { classifyFlows };
