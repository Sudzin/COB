/**
 * Производные показатели потока. Если поток слишком короткий (один пакет или длительность
 * меньше порога), PPS/BPS = null: деление на ~0 даёт миллионы «пакетов в секунду» из ничего.
 */
function computeFlowMetrics(flow, minDurationSec) {
  const duration = flow.end_time - flow.start_time;
  const reliable = flow.packets > 1 && duration >= minDurationSec;
  return {
    duration,
    pps: reliable ? flow.packets / duration : null,
    bps: reliable ? (flow.bytes * 8) / duration : null,
    syn_ratio: flow.packets ? flow.syn_count / flow.packets : 0,
    avg_size: flow.packets ? flow.bytes / flow.packets : 0
  };
}

module.exports = { computeFlowMetrics };
