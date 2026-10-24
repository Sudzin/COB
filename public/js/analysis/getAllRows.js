/** Все строки всех файлов одним списком. */
export function getAllRows(files) {
  return files.flatMap(f => f.rows || []);
}
