import { store } from '../state.js';
import { render } from '../render/render.js';
import { showErrorModal } from '../ui/showErrorModal.js';

export async function loadData() {
  try {
    const res = await fetch('/api/scan');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    store.data = await res.json();
    render();
  } catch (e) {
    showErrorModal('Не удалось связаться с сервером (API недоступно).');
  }
}
