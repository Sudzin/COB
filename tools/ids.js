const fs = require('fs');
const path = require('path');
const config = require('../src/config');
const { parsePcap } = require('../src/core/pcap/parsePcap');
const { parsePacket } = require('../src/core/pcap/parsePacket');
const { aggregateFlows } = require('../src/core/pcap/aggregateFlows');
const { computeFlowMetrics } = require('../src/core/pcap/computeFlowMetrics');
const { loadSignatures } = require('../src/core/signatures/loadSignatures');
const { detectSignatures } = require('../src/core/signatures/detectSignatures');
const {
  filterBySeverity,
  writeAlertsJsonl,
  formatAlertConsole
} = require('../src/core/signatures/alertLogger');

function parseArgs(argv) {
  const opts = {
    target: config.PCAPS_DIR,
    thresholdSeverity: 'LOW',
    signaturesPath: config.SIGNATURES_DIR || path.join(config.ROOT_DIR, 'signatures'),
    outPath: path.join(config.ROOT_DIR, 'ids_alerts.log')
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--threshold-severity' && argv[i + 1]) {
      opts.thresholdSeverity = argv[++i].toUpperCase();
    } else if (arg.startsWith('--threshold-severity=')) {
      opts.thresholdSeverity = arg.split('=')[1].toUpperCase();
    } else if (arg === '--signatures' && argv[i + 1]) {
      opts.signaturesPath = path.resolve(argv[++i]);
    } else if (arg === '--out' && argv[i + 1]) {
      opts.outPath = path.resolve(argv[++i]);
    } else if (!arg.startsWith('-')) {
      opts.target = path.resolve(arg);
    }
  }
  return opts;
}

function collectPcaps(target) {
  const stat = fs.statSync(target);
  if (stat.isFile()) return [target];
  return fs.readdirSync(target)
    .filter(f => config.PCAP_EXTENSIONS.includes(path.extname(f).toLowerCase()))
    .sort()
    .map(f => path.join(target, f));
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  const signatures = loadSignatures(opts.signaturesPath);
  const files = collectPcaps(opts.target);
  const seen = new Set();

  let totalShown = 0;
  for (const file of files) {
    const { linkType, packets: raw } = parsePcap(fs.readFileSync(file));
    const packets = raw.map(r => parsePacket(r, linkType)).filter(Boolean);
    const flows = [...aggregateFlows(packets).values()];
    flows.forEach(f => { f.metrics = computeFlowMetrics(f, config.TRAFFIC.MIN_DURATION_SEC); });

    const allAlerts = detectSignatures(flows, signatures, seen);
    writeAlertsJsonl(opts.outPath, allAlerts);

    const visible = filterBySeverity(allAlerts, opts.thresholdSeverity);
    totalShown += visible.length;

    if (visible.length) {
      console.log(`\n=== ${path.basename(file)} (${visible.length}) ===`);
      visible.forEach(a => console.log(formatAlertConsole(a)));
    }
  }

  console.log(`\nПроверено файлов: ${files.length}, показано алертов (${opts.thresholdSeverity}+): ${totalShown}. Лог: ${opts.outPath}`);
}

main();
