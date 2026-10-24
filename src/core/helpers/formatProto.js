/** Хвост строки после порта ("ssh2" и т.п.) в виде " · ssh2" или пустая строка. */
function formatProto(rest) {
  return rest && rest.trim() ? ' · ' + rest.trim() : '';
}

module.exports = { formatProto };
