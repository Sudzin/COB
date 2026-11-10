/** Конец потока: у ICMP портов нет, поэтому только адрес. */
export function fmtEndpoint(proto, ip, port) {
  return proto === 'ICMP' ? ip : ip + ':' + port;
}
