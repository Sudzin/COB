const OPS = {
  eq:  (a, b) => a === b,
  neq: (a, b) => a !== b,
  gt:  (a, b) => typeof a === 'number' && a > b,
  gte: (a, b) => typeof a === 'number' && a >= b,
  lt:  (a, b) => typeof a === 'number' && a < b,
  lte: (a, b) => typeof a === 'number' && a <= b,
  in:  (a, b) => Array.isArray(b) && b.includes(a)
};

const isBroadcast = ip => ip === '255.255.255.255' || ip.endsWith('.255');

const GROUP_KEYS = {
  src_dst:   f => `${f.initiator.ip}>${f.responder.ip}`,
  src_dport: f => `${f.initiator.ip}>*:${f.responder.port}`,
  dst_dport: f => `${f.responder.ip}:${f.responder.port}`
};

function getField(obj, fieldPath) {
  return fieldPath.split('.').reduce((acc, k) => (acc == null ? undefined : acc[k]), obj);
}

function checkConditions(target, conditions, match = 'all') {
  const method = match === 'any' ? 'some' : 'every';
  return conditions[method](c => {
    const fn = OPS[c.op];
    if (!fn) throw new Error(`Неизвестный оператор в сигнатуре: ${c.op}`);
    return fn(getField(target, c.field), c.value);
  });
}

function enrichFlow(flow) {
  return {
    ...flow,
    is_broadcast: isBroadcast(flow.initiator.ip) || isBroadcast(flow.responder.ip)
  };
}

function summarizeGroup(flows) {
  return {
    flows: flows.length,
    packets: flows.reduce((s, f) => s + f.packets, 0),
    sum_syn: flows.reduce((s, f) => s + f.syn_count, 0),
    unique_dports: new Set(flows.map(f => f.responder.port)).size,
    unique_dsts: new Set(flows.map(f => f.responder.ip)).size,
    unique_srcs: new Set(flows.map(f => f.initiator.ip)).size,
    start_time: Math.min(...flows.map(f => f.start_time))
  };
}

/**
 * Применяет базу сигнатур к массиву потоков с дедупликацией по паре (ключ, сигнатура).
 * @param {Array<object>} flowList потоки после aggregateFlows + computeFlowMetrics
 * @param {Array<object>} signatures активные правила из loadSignatures
 * @param {Set<string>} [seen] внешняя «память» для потокового режима
 */

function detectSignatures(flowList, signatures, seen = new Set()) {
  const alerts = [];
  const enriched = flowList.map(enrichFlow);

  for (const sig of signatures) {
    if (sig.scope === 'flow') {
      for (const f of enriched) {
        if (!checkConditions(f, sig.conditions, sig.match)) continue;
        const dedupKey = `${f.key}|${sig.name}`;
        if (seen.has(dedupKey)) continue;
        seen.add(dedupKey);

        alerts.push({
          timestamp: new Date(f.start_time * 1000).toISOString(),
          src_ip: f.initiator.ip,
          dst_ip: f.responder.ip,
          signature_name: sig.name,
          severity: sig.severity,
          details: `${sig.description} (пакетов: ${f.packets}, pps: ${f.metrics?.pps ? Math.round(f.metrics.pps) : 'n/a'})`
        });
      }
      continue;
    }

    if (sig.scope === 'group') {
      const keyFn = GROUP_KEYS[sig.groupBy];
      if (!keyFn) throw new Error(`Неизвестный groupBy: ${sig.groupBy}`);

      const matched = sig.flowFilter
        ? enriched.filter(f => checkConditions(f, sig.flowFilter, 'all'))
        : enriched;

      const groups = new Map();
      for (const f of matched) {
        const gk = keyFn(f);
        if (!groups.has(gk)) groups.set(gk, []);
        groups.get(gk).push(f);
      }

      for (const [gk, group] of groups) {
        const stats = summarizeGroup(group);
        if (!checkConditions(stats, sig.conditions, sig.match)) continue;
        const dedupKey = `group:${gk}|${sig.name}`;
        if (seen.has(dedupKey)) continue;
        seen.add(dedupKey);

        const first = group[0];
        alerts.push({
          timestamp: new Date(stats.start_time * 1000).toISOString(),
          src_ip: stats.unique_srcs > 1 ? `${stats.unique_srcs} sources` : first.initiator.ip,
          dst_ip: stats.unique_dsts > 1 ? `${stats.unique_dsts} hosts` : first.responder.ip,
          signature_name: sig.name,
          severity: sig.severity,
          details: `${sig.description} (потоков: ${stats.flows}, пакетов: ${stats.packets})`
        });
      }
    }
  }

  return alerts;
}

module.exports = { detectSignatures };
