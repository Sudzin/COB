const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { parsePcap } = require('../src/core/pcap/parsePcap');
const { parsePacket } = require('../src/core/pcap/parsePacket');
const { aggregateFlows } = require('../src/core/pcap/aggregateFlows');
const { computeFlowMetrics } = require('../src/core/pcap/computeFlowMetrics');
const { analyzePcap } = require('../src/core/pcap/analyzePcap');
const { TRAFFIC } = require('../src/config');
const { ipv4Packet, buildPcap } = require('./helpers/buildPcap');

const FIXTURE = path.join(__dirname, '..', 'pcaps', 'lab2_test_traffic.pcap');

function parsed(frames) {
  const { linkType, packets } = parsePcap(buildPcap(frames));
  return packets.map(p => parsePacket(p, linkType)).filter(Boolean);
}

test('parsePcap: сигнатуры и ошибки', () => {
  assert.throws(() => parsePcap(Buffer.from('0a0d0d0a' + '00'.repeat(30), 'hex')), { code: 'ERR_PCAPNG' });
  assert.throws(() => parsePcap(Buffer.alloc(40, 1)), { code: 'ERR_NOT_PCAP' });
  assert.throws(() => parsePcap(Buffer.alloc(5)), { code: 'ERR_NOT_PCAP' });
});

test('parsePcap: оборванная последняя запись не роняет разбор', () => {
  const full = buildPcap([
    { ts: 1, data: ipv4Packet({ src: '1.1.1.1', dst: '2.2.2.2', sport: 1, dport: 2 }) },
    { ts: 2, data: ipv4Packet({ src: '1.1.1.1', dst: '2.2.2.2', sport: 1, dport: 2 }) }
  ]);
  const res = parsePcap(full.subarray(0, full.length - 5));
  assert.strictEqual(res.packets.length, 1);
  assert.strictEqual(res.truncated, true);
});

test('parsePacket: Ethernet + TCP, флаги и порты', () => {
  const ip = ipv4Packet({ src: '10.0.0.1', dst: '10.0.0.2', sport: 1234, dport: 80, flags: ['syn', 'ack'] });
  const eth = Buffer.concat([Buffer.alloc(12), Buffer.from([0x08, 0x00]), ip]);
  const p = parsePacket({ ts: 1, origLen: eth.length, data: eth }, 1);
  assert.deepStrictEqual([p.src, p.dst, p.proto, p.sport, p.dport], ['10.0.0.1', '10.0.0.2', 'TCP', 1234, 80]);
  assert.deepStrictEqual([p.flags.syn, p.flags.ack, p.flags.rst], [true, true, false]);
});

test('parsePacket: не-IP кадры (ARP) и чужие протоколы игнорируются', () => {
  const arp = Buffer.concat([Buffer.alloc(12), Buffer.from([0x08, 0x06]), Buffer.alloc(28)]);
  assert.strictEqual(parsePacket({ ts: 1, origLen: arp.length, data: arp }, 1), null);
  const ip = ipv4Packet({ src: '1.1.1.1', dst: '2.2.2.2' });
  ip[9] = 47; // GRE
  assert.strictEqual(parsePacket({ ts: 1, origLen: ip.length, data: ip }, 101), null);
});

test('aggregateFlows: A→B и B→A — один поток (симметричный анализ)', () => {
  const flows = aggregateFlows(parsed([
    { ts: 1.0, data: ipv4Packet({ src: '10.0.0.1', dst: '93.1.1.1', sport: 50000, dport: 443, flags: ['syn'] }) },
    { ts: 1.1, data: ipv4Packet({ src: '93.1.1.1', dst: '10.0.0.1', sport: 443, dport: 50000, flags: ['syn', 'ack'] }) },
    { ts: 1.2, data: ipv4Packet({ src: '10.0.0.1', dst: '93.1.1.1', sport: 50000, dport: 443, flags: ['ack'] }) }
  ]));
  assert.strictEqual(flows.size, 1);
  const f = [...flows.values()][0];
  assert.strictEqual(f.packets, 3);
  assert.deepStrictEqual([f.fwd.packets, f.rev.packets], [2, 1]);
  assert.deepStrictEqual([f.initiator.ip, f.initiator.port], ['10.0.0.1', 50000]);
  assert.deepStrictEqual([f.syn_count, f.ack_count], [2, 2]);
  assert.ok(Math.abs(f.end_time - f.start_time - 0.2) < 1e-6);
});

test('aggregateFlows: разные порты и протоколы — разные потоки', () => {
  const flows = aggregateFlows(parsed([
    { ts: 1, data: ipv4Packet({ src: '10.0.0.1', dst: '10.0.0.2', sport: 1, dport: 53, proto: 'UDP' }) },
    { ts: 1, data: ipv4Packet({ src: '10.0.0.1', dst: '10.0.0.2', sport: 1, dport: 53, proto: 'TCP' }) },
    { ts: 1, data: ipv4Packet({ src: '10.0.0.1', dst: '10.0.0.2', sport: 2, dport: 53, proto: 'UDP' }) }
  ]));
  assert.strictEqual(flows.size, 3);
});

test('computeFlowMetrics: PPS/BPS не считаются на нулевой длительности', () => {
  const [single] = aggregateFlows(parsed([
    { ts: 1, data: ipv4Packet({ src: '1.1.1.1', dst: '2.2.2.2', sport: 1, dport: 2, flags: ['syn'] }) }
  ])).values();
  const m = computeFlowMetrics(single, TRAFFIC.MIN_DURATION_SEC);
  assert.strictEqual(m.pps, null);
  assert.strictEqual(m.bps, null);
  assert.strictEqual(m.syn_ratio, 1);

  const [two] = aggregateFlows(parsed([
    { ts: 1, data: ipv4Packet({ src: '1.1.1.1', dst: '2.2.2.2', sport: 1, dport: 2 }) },
    { ts: 2, data: ipv4Packet({ src: '1.1.1.1', dst: '2.2.2.2', sport: 1, dport: 2 }) }
  ])).values();
  const m2 = computeFlowMetrics(two, TRAFFIC.MIN_DURATION_SEC);
  assert.strictEqual(m2.pps, 2);
  assert.strictEqual(m2.bps, 2 * 40 * 8 / 1);
});

test('lab2_test_traffic.pcap: разбор и классификация', () => {
  const r = analyzePcap(fs.readFileSync(FIXTURE), 'lab2_test_traffic.pcap', TRAFFIC);
  assert.strictEqual(r.totalPackets, 240);
  assert.strictEqual(r.ignoredPackets, 0);
  assert.deepStrictEqual(r.protocols, { TCP: 195, UDP: 20, ICMP: 25 });

  const cat = r.categories;
  assert.strictEqual(cat.legit.packets, 110);
  assert.strictEqual(cat.scan.packets, 15);
  assert.strictEqual(cat.synflood.packets, 100);
  assert.strictEqual(cat.icmp.packets, 15);

  const byType = Object.fromEntries(r.incidents.map(i => [i.type, i]));
  assert.strictEqual(r.incidents.length, 3);
  assert.strictEqual(byType.scan.src, '203.0.113.100');
  assert.strictEqual(byType.scan.dst, '192.168.1.50');
  assert.strictEqual(byType.synflood.dst, '192.168.1.100:80');
  assert.strictEqual(byType.synflood.sources_count, 20);
  assert.strictEqual(byType.icmp.dst, '192.168.1.255');
});

test('lab2_test_traffic.pcap: обычный ping на 8.8.8.8 не считается аномалией', () => {
  const r = analyzePcap(fs.readFileSync(FIXTURE), 'x.pcap', TRAFFIC);
  const ping = r.flows.find(f => f.proto === 'ICMP' && f.dst === '8.8.8.8');
  assert.strictEqual(ping.category, 'legit');
});
