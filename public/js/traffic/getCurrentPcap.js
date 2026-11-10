import { store } from '../state.js';

/** Анализ выбранного .pcap (только успешно разобранный) или null. */
export function getCurrentPcap() {
  const files = store.traffic && store.traffic.files;
  const cur = files && files.find(f => f.fileName === store.currentPcap);
  return cur && cur.status === 'OK' ? cur : null;
}
